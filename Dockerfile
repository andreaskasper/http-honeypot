FROM golang:1.16

WORKDIR /go/src/app

ADD src/ /go/src/app/

#RUN go get -d -v honeypot.go
RUN go install -v honeypot.go

CMD ["honeypot"]
