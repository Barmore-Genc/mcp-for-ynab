# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS
ARG TARGETARCH
# The build context excludes .git, so the binary cannot date itself from the
# commit. CI passes the tag, or dev-<date>.
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Pure Go with cgo off, so the build host cross-compiles rather than emulating,
# and the binary needs no loader in the runtime image.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /mcp-for-ynab ./cmd/mcp-for-ynab

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /mcp-for-ynab /mcp-for-ynab
EXPOSE 8080
ENV MCP_ADDR=:8080
ENTRYPOINT ["/mcp-for-ynab"]
