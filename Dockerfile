FROM golang:1.20-alpine
RUN mkdir /app
COPY . /app
WORKDIR /app
RUN go build -o server .
VOLUME [ "/app/dbdata", "/app/files" ]
ENTRYPOINT [ "/app/server" ]
CMD [ "-logtype", "json" ]
