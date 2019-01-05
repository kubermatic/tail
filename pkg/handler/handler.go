package handler

import (
	"context"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/dghubble/gologin"
	"github.com/dghubble/gologin/github"
	"github.com/dghubble/sessions"
	gogithub "github.com/google/go-github/github"
	"golang.org/x/oauth2"
	githubOAuth2 "golang.org/x/oauth2/github"
)

var repoName = regexp.MustCompile("/pull/[a-zA-Z_-]+")

const (
	// The "build/<<bucket-name>>/pr-logs/pull" prefix is required in order for Spyglass to be able
	// to render correct links:
	// * https://github.com/kubernetes/test-infra/blob/5475440d76f9039f7e1a5fa86c2f85ea8414b093/prow/cmd/deck/static/prow/prow.ts#L536
	// * https://github.com/kubernetes/test-infra/blob/5475440d76f9039f7e1a5fa86c2f85ea8414b093/prow/cmd/deck/main.go#L508
	pathCheckerRegexpTemplate = "build/%s/pr-logs/pull/[a-zA-Z_-]+/[0-9]+/[\\. 0-9a-zA-Z_-]+/[0-9]+"
	sessionName               = "prow"
	sessionUserKey            = "username"
)

// sessionStore encodes and decodes session data stored in signed cookies
var sessionStore = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")), nil)

type prowBucketHandler struct {
	bucket       *storage.BucketHandle
	bucketName   string
	tmpDir       string
	publicRepos  []string
	org          string
	githubClient *gogithub.Client
	pathChecker  *regexp.Regexp
}

func New(bucketName string, cacheDir, listenAddress, clientID, clientSecret, redirectURL, org string, publicRepos []string, githubClient *gogithub.Client) (*http.Server, error) {
	ctx := context.Background()
	storageClient, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage client: %v", err)
	}
	bkt := storageClient.Bucket(bucketName)
	pathChecker, err := regexp.Compile(fmt.Sprintf(pathCheckerRegexpTemplate, bucketName))
	if err != nil {
		return nil, fmt.Errorf("failed to compile pathchecker regexp: %v", err)
	}
	bucketHandler := &prowBucketHandler{bucket: bkt, bucketName: bucketName, tmpDir: cacheDir, publicRepos: publicRepos, org: org, githubClient: githubClient, pathChecker: pathChecker}

	mux := &http.ServeMux{}
	mux.HandleFunc("/", bucketHandler.router)
	mux.HandleFunc("/logout", logoutHandler)

	oauth2Config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     githubOAuth2.Endpoint,
	}
	stateConfig := gologin.DefaultCookieConfig
	mux.Handle("/github/login", github.StateHandler(stateConfig, github.LoginHandler(oauth2Config, nil)))
	mux.Handle("/github/callback", github.StateHandler(stateConfig, github.CallbackHandler(oauth2Config, bucketHandler.issueSession(), nil)))

	return &http.Server{
		Addr:         listenAddress,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}, nil
}

func (pbh *prowBucketHandler) router(resp http.ResponseWriter, req *http.Request) {
	if strings.HasPrefix(req.URL.String(), "/build") {
		pbh.handleLogRequest(resp, req)
		return
	}

	if req.URL.Path != "/" {
		http.NotFound(resp, req)
		return
	}

	if !isAuthenticated(req) {
		tmpl, err := template.ParseFiles("/var/tmp/login.html")
		if err != nil {
			log.Print(err)
		}
		if err := tmpl.Execute(resp, pbh.org); err != nil {
			log.Print(err)
		}
	}
}

// logoutHandler destroys the session on POSTs and redirects to home.
func logoutHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method == "POST" {
		sessionStore.Destroy(w, sessionName)
	}
	http.Redirect(w, req, "/", http.StatusFound)
}

func (pbh *prowBucketHandler) handleLogRequest(resp http.ResponseWriter, req *http.Request) {
	log.Printf("Got request for %s", req.URL.Path)
	if !pbh.pathChecker.MatchString(req.URL.Path) {
		resp.WriteHeader(http.StatusForbidden)
		return
	}

	// check if the requested repo is private
	match := repoName.FindStringSubmatch(req.URL.Path)
	var repo string
	if match != nil && len(match) == 1 {
		repo = match[0] // will be a string of the form /pull/org_repo
		repo = strings.Replace(repo, "/pull/", "", -1)
		// Lets hope we never have a repo or org with an underscore in its name...
		repo = strings.Replace(repo, "_", "/", -1)
	}

	if !contains(pbh.publicRepos, repo) && !isAuthenticated(req) {
		log.Printf("%s is not in the list of public repos %v", repo, pbh.publicRepos)
		tmpl, err := template.ParseFiles("/var/tmp/login.html")
		if err != nil {
			log.Print(err)
		}
		if err := tmpl.Execute(resp, pbh.org); err != nil {
			log.Print(err)
		}
		return
	}

	pbh.showLogs(resp, req)
}

// issueSession issues a cookie session after successful Github login
func (pbh *prowBucketHandler) issueSession() http.Handler {
	fn := func(resp http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		githubUser, err := github.UserFromContext(ctx)
		if err != nil {
			http.Error(resp, err.Error(), http.StatusInternalServerError)
			return
		}
		username := *githubUser.Login

		isMember, _, err := pbh.githubClient.Organizations.IsMember(ctx, pbh.org, username)
		if err != nil {
			http.Error(resp, err.Error(), http.StatusInternalServerError)
			return
		}

		if !isMember {
			_, err := fmt.Fprintf(resp, `<p>Hey, %s</p>`, username)
			if err != nil {
				http.Error(resp, err.Error(), http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(resp, `<p>Only members of the %s organisation are allowed to view this page. Looks like you are not a member. :(</p>`, pbh.org)
			return
		}

		session := sessionStore.New(sessionName)
		session.Values[sessionUserKey] = username
		session.Save(resp)
		http.Redirect(resp, req, req.Header.Get("Referer"), http.StatusFound)
	}
	return http.HandlerFunc(fn)
}

// showLogs displays the logs from the specified bucket.
func (pbh *prowBucketHandler) showLogs(resp http.ResponseWriter, req *http.Request) {
	bucketPath := strings.Replace(req.URL.Path, fmt.Sprintf("/build/%s/", pbh.bucketName), "", -1)
	bucketPath = bucketPath + "/build-log.txt"
	cachePath := path.Join(pbh.tmpDir, strings.Replace(bucketPath, "/", "_", -1))
	cachePath = strings.Replace(cachePath, " ", "_", -1)
	if _, err := os.Stat(cachePath); err != nil {
		if !os.IsNotExist(err) {
			resp.WriteHeader(http.StatusInternalServerError)
			log.Printf("Failed to check if cache for file exists %s: %v", cachePath, err)
			return
		}

		log.Printf("Requesting file %s from bucket", bucketPath)
		obj := pbh.bucket.Object(bucketPath)
		reader, err := obj.NewReader(context.Background())
		if err != nil {
			if err == storage.ErrObjectNotExist {
				// Be optimistic and assume:
				// * The object wasnt found because the build is still running
				// * Deck runs on the same base url as tail
				slashSplitURL := strings.Split(req.URL.String(), "/")
				// Should never happen but still check
				if len(slashSplitURL) < 2 {
					resp.WriteHeader(http.StatusInternalServerError)
					log.Printf("Failed to get obj reader for %s with len(slashSplitURL) < 2: %v", bucketPath, err)
					return
				}
				jobName := slashSplitURL[len(slashSplitURL)-2]
				buildID := slashSplitURL[len(slashSplitURL)-1]
				// Req.URL contains neither a scheme nor a host, we can get the host from req
				// directly but not the scheme - We assume it always is https
				redirectURL := fmt.Sprintf("https://%s/log?job=%s&id=%s", req.Host, jobName, buildID)
				http.Redirect(resp, req, redirectURL, http.StatusTemporaryRedirect)
				return
			}
			resp.WriteHeader(http.StatusInternalServerError)
			log.Printf("Failed to get obj reader for %s: %v", bucketPath, err)
			return
		}
		data, err := ioutil.ReadAll(reader)
		if err != nil {
			resp.WriteHeader(http.StatusInternalServerError)
			log.Printf("Failed to read data for %s: %v", bucketPath, err)
			return
		}
		if err := reader.Close(); err != nil {
			resp.WriteHeader(http.StatusInternalServerError)
			log.Printf("failed to close reader for %s: %v", bucketPath, err)
			return
		}
		if err := ioutil.WriteFile(cachePath, data, 0600); err != nil {
			resp.WriteHeader(http.StatusInternalServerError)
			log.Printf("Failed to write cache file for %s: %v", cachePath, err)
			return
		}

	}

	data, err := ioutil.ReadFile(cachePath)
	if err != nil {
		resp.WriteHeader(http.StatusInternalServerError)
		log.Printf("Failed to read cache file for %s: %v", cachePath, err)
		return
	}

	if _, err := resp.Write(data); err != nil {
		log.Printf("failed to write data for %s: %v", bucketPath, err)
	}
}

func contains(publicRepos []string, repo string) bool {
	for _, s := range publicRepos {
		if s == repo {
			return true
		}
	}
	return false
}

// isAuthenticated returns true if the user has a signed session cookie.
func isAuthenticated(req *http.Request) bool {
	if _, err := sessionStore.Get(req, sessionName); err == nil {
		return true
	}
	return false
}
