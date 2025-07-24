FROM golang:1.23.0-bullseye as builder

# Override the default value of GOOS when building the Docker image using the --build-arg flag
ARG GOOS=linux
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /build
# Copy the code into the container
COPY . .
RUN go mod download

# Build the application statically with version info
RUN echo "Building blobber with commit ${GIT_COMMIT}..." && \
    GOOS=${GOOS} go build -ldflags "-X main.gitCommit=${GIT_COMMIT} -X main.buildDate=${BUILD_DATE}" -o blobber.bin ./cmd/blobber.go && \
    echo "Build complete, binary size:" && \
    ls -la blobber.bin

FROM debian:bullseye-slim

COPY --from=builder /build/blobber.bin /blobber.bin

RUN apt-get update && apt-get install -y curl

# Ensure the binary is executable
RUN chmod +x /blobber.bin

# Add a version check
RUN echo "Testing binary..." && /blobber.bin --help 2>&1 | head -5 || true

ENTRYPOINT ["/blobber.bin"]
