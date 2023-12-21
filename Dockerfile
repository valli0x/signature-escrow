FROM --platform=$BUILDPLATFORM golang:1.19-alpine AS build-env

WORKDIR /go/src/github.com/valli0x/signature-escrow

COPY . .

ARG TARGETARCH=amd64
ARG TARGETOS=linux
ARG CGO_ENABLED=0

RUN GOARCH=${TARGETARCH} CGO_ENABLED=${CGO_ENABLED} GOOS=${TARGETOS} go build -o build/signature-escrow main.go 

FROM alpine:edge

RUN apk add --no-cache ca-certificates

WORKDIR /root

USER nobody

COPY --from=build-env /go/src/github.com/valli0x/signature-escrow/build/signature-escrow  /usr/bin/signature-escrow

CMD ["signature-escrow"]