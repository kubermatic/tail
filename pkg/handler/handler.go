package handler

import (
	"context"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"cloud.google.com/go/storage"
)

var pathChecker = regexp.MustCompile("logs/[a-zA-Z_-]+/[0-9]+/[ a-zA-Z_-]+/[0-9]+")

type prowBucketHandler struct {
	bucket *storage.BucketHandle
	tmpDir string
}

func New(b *storage.BucketHandle, cacheDir, listenAddress string) *http.Server {
	bucketHandler := &prowBucketHandler{bucket: b, tmpDir: cacheDir}
	mux := &http.ServeMux{}
	mux.HandleFunc("/", bucketHandler.router)
	return &http.Server{
		Addr:         listenAddress,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
}

func (pbh *prowBucketHandler) router(resp http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.String(), "/logs") {
		pbh.handleLogRequest(resp, r)
		return
	}
	resp.WriteHeader(http.StatusNotFound)
}

func (pbh *prowBucketHandler) handleLogRequest(resp http.ResponseWriter, r *http.Request) {
	log.Printf("Got request for %s", r.URL.Path)
	if !pathChecker.MatchString(r.URL.Path) {
		resp.WriteHeader(http.StatusNotFound)
		return
	}

	bucketPath := strings.Replace(r.URL.Path, "/logs", "pr-logs/pull", 1)
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
