FROM golang:1.22-alpine

WORKDIR /app

COPY . .

WORKDIR /app/

RUN go mod download

WORKDIR /app

# build platform app
RUN go build 

EXPOSE 8080
CMD ["/app/helloworld"]
