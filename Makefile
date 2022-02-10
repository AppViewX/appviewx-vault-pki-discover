.PHONY:

GIT_COMMIT := $(shell git rev-list -1 HEAD)

build:
	go build -ldflags "-X main.gitCommit=$(GIT_COMMIT)" -o appviewx_vault_util .