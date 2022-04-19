FROM golang:1.18.1
COPY . /app
RUN cd /app && env GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -o fanotify-mon

FROM registry.fedoraproject.org/fedora:35
COPY --from=0 /app/fanotify-mon /fanotify-mon
ENTRYPOINT [ "/fanotify-mon" ]
