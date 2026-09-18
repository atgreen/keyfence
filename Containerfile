FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -buildvcs=false -o /keyfence ./cmd/keyfence

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /keyfence /usr/local/bin/keyfence
EXPOSE 10210 10211 10212

# KeyFence binds loopback by default, which is right on a host and wrong in a
# container: a published port is forwarded to the container's own address, so a
# loopback-only listener could not be reached from outside the pod. These are
# ordinary arguments, so passing -proxy or -api again overrides them.
ENTRYPOINT ["keyfence", \
            "-proxy", "0.0.0.0:10210", \
            "-ssh", "0.0.0.0:10211", \
            "-api", "0.0.0.0:10212"]
