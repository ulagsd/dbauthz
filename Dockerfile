# syntax=docker/dockerfile:1

# --- build ---------------------------------------------------------------
FROM golang:1.26-alpine AS build

WORKDIR /src

# Dependencies first so a source edit does not re-download the module cache.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/dbiam-server ./cmd/dbiam-server \
 && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/dbiam ./cmd/dbiam

# --- runtime -------------------------------------------------------------
# Static distroless: no shell, no package manager, nothing to pivot to if the
# process is compromised. The console is embedded in the binary, so this image
# needs no web server and no assets on disk.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/dbiam-server /usr/local/bin/dbiam-server
COPY --from=build /out/dbiam        /usr/local/bin/dbiam

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/dbiam-server"]
