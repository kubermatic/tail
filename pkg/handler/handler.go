package handler

import (
	"context"
	"fmt"
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

var pathChecker = regexp.MustCompile("logs/[a-zA-Z_-]+/[0-9]+/[ 0-9a-zA-Z_-]+/[0-9]+")
var repoName = regexp.MustCompile("/logs/[a-zA-Z_-]+")

const (
	sessionName    = "prow"
	sessionUserKey = "username"
)

// sessionStore encodes and decodes session data stored in signed cookies
var sessionStore = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")), nil)

type prowBucketHandler struct {
	bucket       *storage.BucketHandle
	tmpDir       string
	publicRepos  []string
	org          string
	githubClient *gogithub.Client
}

func New(b *storage.BucketHandle, cacheDir, listenAddress, clientID, clientSecret, redirectURL, org string, publicRepos []string, githubClient *gogithub.Client) *http.Server {
	bucketHandler := &prowBucketHandler{bucket: b, tmpDir: cacheDir, publicRepos: publicRepos, org: org, githubClient: githubClient}

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
	}
}

func (pbh *prowBucketHandler) router(resp http.ResponseWriter, req *http.Request) {
	if strings.HasPrefix(req.URL.String(), "/logs") {
		pbh.handleLogRequest(resp, req)
		return
	}

	if req.URL.Path != "/" {
		http.NotFound(resp, req)
		return
	}

	if !isAuthenticated(req) {
		page, _ := ioutil.ReadFile("pkg/handler/login.html")
		fmt.Fprintf(resp, string(page))
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
	if !pathChecker.MatchString(req.URL.Path) {
		resp.WriteHeader(http.StatusForbidden)
		return
	}

	// check if the requested repo is private
	match := repoName.FindStringSubmatch(req.URL.Path)
	var repo string
	if match != nil && len(match) == 1 {
		repo = match[0] // will be a string of the form /logs/org_repo
		repo = strings.Replace(repo[6:], "_", "/", -1)
	}

	if !contains(pbh.publicRepos, repo) && !isAuthenticated(req) {
		page, _ := ioutil.ReadFile("pkg/handler/login.html")
		fmt.Fprintf(resp, string(page))
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
			_, err := fmt.Fprintf(resp, `Hey, %s`, username)
			if err != nil {
				http.Error(resp, err.Error(), http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(resp, `Only members of the %s organisation are allowed to view this page. Looks like you are not a member. :(`, pbh.org)
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
	bucketPath := strings.Replace(req.URL.Path, "/logs", "pr-logs/pull", 1)
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
