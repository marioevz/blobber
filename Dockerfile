FROM golang:1.20.10-bullseye as builder

# Override the default value of GOOS when building the Docker image using the --build-arg flag
ARG GOOS=linux


WORKDIR /build
# Copy the code into the container
COPY . .
RUN go mod download

# Build the application statically
RUN cd cmd && GOOS=${GOOS} go build -o blobber.bin .

FROM debian:bullseye-slim

COPY --from=builder /build/cmd/blobber.bin /blobber.bin

RUN apt-get update && apt-get install -y curl

# Ensure the binary is executable
RUN chmod +x /blobber.bin

ENTRYPOINT ["/blobber.bin"]
