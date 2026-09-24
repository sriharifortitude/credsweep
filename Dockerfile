FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /credsweep ./cmd/credsweep

# credsweep shells out to a real `git` binary (see docs/adr/0001), so
# unlike a pure-Go static binary this image cannot run on distroless:
# nonroot -- it needs git and libc present. Alpine is the smallest base
# that has both.
FROM alpine:3.20
RUN apk add --no-cache git && \
    adduser -D -u 10001 credsweep && \
    git config --system --add safe.directory '*'
# safe.directory '*' trusts every repository this container is ever
# pointed at (git otherwise refuses a repo owned by a different UID than
# the one running it, which a bind-mounted host repo always is here).
# That is the correct trust boundary for a throwaway scanning container,
# not for a general-purpose git image.
COPY --from=build /credsweep /usr/local/bin/credsweep
USER credsweep
ENTRYPOINT ["credsweep"]
