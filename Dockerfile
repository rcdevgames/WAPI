# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY ./src/go.mod ./src/go.sum ./
RUN go mod download

COPY ./src/ .

RUN go build -o main .

# Final stage
FROM gcr.io/distroless/static-debian12

COPY --from=builder /app/main /app/main

# Debugging steps
RUN echo "Checking contents:" && ls -l /app
RUN echo "Attempting to execute binary:" && /app/main --help || true

EXPOSE 3000

CMD ["/app/main", "-port=3000"]
