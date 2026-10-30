FROM golang:1.27.3 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY third_party/scs ./third_party/scs
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/server ./cmd/server \
    && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o /out/agent.exe ./cmd/agent \
    && mkdir -p /out/rootfs/data \
    && chmod 700 /out/rootfs/data \
    && chown 65532:65532 /out/rootfs/data

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /usr/share/doc/ca-certificates/copyright /app/CA_CERTIFICATES_NOTICE
COPY --from=build /out/server /app/server
COPY --from=build /out/agent.exe /app/agent.exe
# Copy the parent tree so /data is an actual source entry with mode 0700.
# Copying an empty directory directly creates a destination with mode 0755.
COPY --from=build --chown=65532:65532 /out/rootfs/ /
COPY LICENSE THIRD_PARTY_NOTICES.md /app/
USER 65532:65532
WORKDIR /data
EXPOSE 8443 8080
ENTRYPOINT ["/app/server"]
