FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /keyfence ./cmd/keyfence

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /keyfence /usr/local/bin/keyfence
EXPOSE 10210 10212
ENTRYPOINT ["keyfence"]
