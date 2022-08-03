#!/usr/bin/make -f


all: cosmovisor test

cosmovisor:
	go install -mod=readonly ./cmd/cosmovisor

test:
	go test -mod=readonly -race ./...

.PHONY: all cosmovisor test
