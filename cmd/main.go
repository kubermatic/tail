package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	gogithub "github.com/google/go-github/github"
	"github.com/kubermatic/tail/pkg/handler"
	"golang.org/x/oauth2"
)

var (
	bucketName, cacheDir, listenPort, publicRepos, redirectURL, org string
)

func main() {
	flag.StringVar(&bucketName, "bucket-name", "prow-data", "Name of the bucket where logs are stored.")
	flag.StringVar(&cacheDir, "cache-dir", "./", "The directory to use for caching.")
	flag.StringVar(&listenPort, "listen-port", ":8080", "Port to listen on.")
	flag.StringVar(&publicRepos, "public-repos", "", "Comma separated list of public repos in format org/repo. Optional.")
	flag.StringVar(&redirectURL, "redirect-url", "http://localhost:8080/github/callback", "The callback URL for the app. Should end with \"/github/callback\".")
	flag.StringVar(&org, "org", "", "The GitHub organization name whose members can access these logs. Required.")
	flag.Parse()

	if org == "" {
		usageAndExit("The -org value cannot be empty.", 1)
	}

	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	token := os.Getenv("TOKEN")

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
	githubclient := gogithub.NewClient(tc)

	server, err := handler.New(bucketName, cacheDir, listenPort, clientID, clientSecret, redirectURL, org, strings.Split(publicRepos, ","), githubclient)
	if err != nil {
		log.Fatalf("failed to create server: %v", err)
	}

	log.Printf("Starting to listen on %s", listenPort)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
}

func usageAndExit(message string, exitCode int) {
	if message != "" {
		fmt.Fprintf(os.Stderr, message)
		fmt.Fprintf(os.Stderr, "\n\n")
	}
	flag.Usage()
	os.Exit(exitCode)
}
