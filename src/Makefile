BIN := ganted
GANTED2RADIUS_BIN := ganted2radius
GOFLAGS := -ldflags='-s -w'

.PHONY: all

all: $(BIN) $(GANTED2RADIUS_BIN)

$(BIN): $(filter-out ganted2radius.go, $(wildcard *.go)) go.mod go.sum
	go build $(GOFLAGS) -o "$@" "$<"

$(GANTED2RADIUS_BIN): ganted2radius.go
	go build $(GOFLAGS) -o "$@" "$<"
