APP_NAME := tranzia
BIN_DIR := bin
IMAGE ?= tranzia
TAG ?= dev

.PHONY: all build clean
all: build

build:
	go mod tidy
	go build -o $(BIN_DIR)/$(APP_NAME) ./cmd/main.go

.PHONY: docker-build-dev
docker-build-dev:
	docker build -t $(IMAGE):$(TAG) .

clean:
	rm -rf $(BIN_DIR)

.PHONY: docs
docs:
	go run ./cmd/doc

.PHONY: test
test:
	@echo "Running all tests..."
	@go test ./... -v $(if $(COVERAGE),-cover)