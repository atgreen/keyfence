.PHONY: build test clean

BINARY := keyfence
BUILD_DIR := ./bin

build:
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/keyfence

test:
	./scripts/test.sh

clean:
	rm -rf $(BUILD_DIR)
