FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build-env

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETARCH=amd64
ARG TARGETOS=linux
ARG CGO_ENABLED=0

RUN GOARCH=${TARGETARCH} CGO_ENABLED=${CGO_ENABLED} GOOS=${TARGETOS} \
    go build -trimpath -ldflags="-s -w" -o /out/signature-escrow .

FROM alpine:3.20

RUN apk add --no-cache ca-certificates && \
    addgroup -S app && adduser -S app -G app

COPY --from=build-env /out/signature-escrow /usr/local/bin/signature-escrow

USER app
WORKDIR /home/app

ENTRYPOINT ["signature-escrow"]
