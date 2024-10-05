
# The build stage
FROM golang:alpine as builder
RUN apk add --no-cache build-base
WORKDIR /app
COPY ./src .
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o rmodz-wa .

# The run stage
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/rmodz-wa .

# Debugging steps
RUN echo "Checking contents:" && ls -l /app
RUN echo "Attempting to execute binary:" && ./rmodz-wa --help || true

EXPOSE 3000
VOLUME ["/app"]
CMD ["./rmodz-wa", "-port=3000"]
