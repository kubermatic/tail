export CGO_ENABLED=0

tail: $(shell find . -name '*.go')
	go build -o tail ./cmd

image: tail
	docker build -t quay.io/kubermatic/tail:$(shell cat VERSION) .
	docker push quay.io/kubermatic/tail:$(shell cat VERSION)
