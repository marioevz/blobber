# Get git commit hash
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build flags
LDFLAGS := -ldflags "-X main.gitCommit=$(GIT_COMMIT) -X main.buildDate=$(BUILD_DATE)"

# Default target
.PHONY: all
all: build

# Build the binary
.PHONY: build
build:
	go build $(LDFLAGS) -o blobber ./cmd

# Build with race detector
.PHONY: build-race
build-race:
	go build -race $(LDFLAGS) -o blobber ./cmd

# Clean build artifacts
.PHONY: clean
clean:
	rm -f blobber

# Run tests
.PHONY: test
test:
	go test -v ./...

# Run tests with race detector
.PHONY: test-race
test-race:
	go test -race -v ./...

# Run linter
.PHONY: lint
lint:
	golangci-lint run --new-from-rev="origin/master"

# Docker build
.PHONY: docker-build
docker-build:
	docker build --build-arg GIT_COMMIT=$(GIT_COMMIT) --build-arg BUILD_DATE=$(BUILD_DATE) -t blobber:latest .

# Show version info
.PHONY: version
version:
	@echo "Git Commit: $(GIT_COMMIT)"
	@echo "Build Date: $(BUILD_DATE)"