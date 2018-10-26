package main

import (
	"context"
	"flag"
	"log"

	"github.com/kubermatic/tail/pkg/handler"

	"cloud.google.com/go/storage"
)

var (
	bucketName, cacheDir, listenPort string
)

func main() {
	flag.StringVar(&bucketName, "bucket-name", "prow-data", "Name of the bucket")
	flag.StringVar(&cacheDir, "cache-dir", "./", "The directory to use for caching")
	flag.StringVar(&listenPort, "listen-port", ":5000", "Port to listen on")
	flag.Parse()

	ctx := context.Background()
	client, err := storage.NewClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create storage client: %v", err)
	}

	bkt := client.Bucket(bucketName)
	server := handler.New(bkt, cacheDir, listenPort)

	log.Printf("Starting to listen on %s", listenPort)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
}
