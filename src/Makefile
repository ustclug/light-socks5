BIN := ganted
GOFLAGS := -ldflags='-s -w'

.PHONY: all

all: $(BIN)

$(BIN): $(wildcard *.go) go.mod go.sum
	go build $(GOFLAGS) -o "$@"
