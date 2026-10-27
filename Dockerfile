FROM golang:1.26-bookworm AS build

WORKDIR /src

RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*

ENV CGO_ENABLED=1
ENV GOPROXY=https://goproxy.cn,direct
ENV GOFLAGS=-buildvcs=false

COPY go.mod ./
COPY . .
RUN go mod tidy && mkdir -p /out && go build -buildmode=c-shared -o /out/codearts.so ./cmd/plugin

FROM scratch
COPY --from=build /out/codearts.so /codearts.so
