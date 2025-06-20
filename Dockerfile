FROM golang:1.21.7-bullseye as builder

# Override the default value of GOOS when building the Docker image using the --build-arg flag
ARG GOOS=linux


WORKDIR /build
# Copy the code into the container
COPY . .
RUN go mod download

# Build the application statically
RUN GOOS=${GOOS} go build -o blobber.bin ./cmd/blobber.go

FROM debian:bullseye-slim

COPY --from=builder /build/blobber.bin /blobber.bin

RUN apt-get update && apt-get install -y curl

# Ensure the binary is executable
RUN chmod +x /blobber.bin

ENTRYPOINT ["/blobber.bin"]
