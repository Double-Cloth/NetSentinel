FROM golang:1.27.1-bookworm AS build
WORKDIR /src
COPY engine/go.mod engine/go.mod
COPY backend/go.mod backend/go.sum backend/
RUN cd backend && go mod download
COPY engine/ engine/
COPY backend/ backend/
RUN cd backend && CGO_ENABLED=0 go build -trimpath -o /out/server ./cmd/server

FROM debian:bookworm-slim
RUN groupadd --gid 10001 netsentinel \
    && useradd --uid 10001 --gid netsentinel --no-create-home netsentinel \
    && mkdir /app /data \
    && chown netsentinel:netsentinel /app /data
COPY --from=build /out/server /app/server
USER 10001:10001
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["/app/server"]
