FROM golang:1.8.3-alpine3.6

RUN mkdir -p /go/src/app
WORKDIR /go/src/app

COPY . /go/src/app
RUN apk add --no-cache git && \
    go-wrapper download && \
    apk del git 
RUN go-wrapper install

EXPOSE 4242
EXPOSE 9142

CMD ["go-wrapper", "run"]
