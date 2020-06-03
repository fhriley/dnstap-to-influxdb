FROM golang:1.14-alpine as builder
RUN apk --no-cache add git
WORKDIR /go/src/app
ADD . .
RUN go get ./...
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o main .
FROM scratch
COPY --from=builder /go/src/app/main /app
ENTRYPOINT ["/app"]
