FROM golang:1 AS builder
WORKDIR /app

# Get Golang dependencies for better caching.
COPY go.mod go.sum ./
RUN go mod download

# Copy in the code.
COPY . .

# Build the code.
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags "-s -w" -o jcp -trimpath cmd/proxy/*.go

# The actual image being produced.
FROM alpine
COPY --from=builder /app/jcp /jcp
CMD ["/jcp"]
