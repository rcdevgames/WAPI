FROM golang:1.20-alpine as builder
ENV APP_HOME /app

WORKDIR "$APP_HOME"
COPY src/ .

RUN go mod download
RUN go mod verify
RUN go build -o wapi

FROM golang:1.20-alpine
ENV APP_HOME /app

RUN mkdir -p "$APP_HOME"
WORKDIR "$APP_HOME"

COPY --from=builder "$APP_HOME"/wapi $APP_HOME
VOLUME [ "$APP_HOME/dbdata", "$APP_HOME/files" ]

EXPOSE 80
CMD ["./wapi", "-logtype", "json"]
