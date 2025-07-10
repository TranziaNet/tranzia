APP_NAME := tranzia
BIN_DIR := bin

.PHONY: all build clean

all: build

build:
	go build -o $(BIN_DIR)/$(APP_NAME) ./cmd/main.go

clean:
	rm -rf $(BIN_DIR)