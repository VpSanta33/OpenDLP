# syntax=docker/dockerfile:1
# OpenDLP 镜像：Go 后端 + 前端静态资源，运行于 distroless（非 root）
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
ARG VERSION=3.3.0
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/opendlp ./cmd/opendlp

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/opendlp /app/opendlp
COPY frontend/ /app/frontend/
ENV OPENDLP_ADDR=0.0.0.0:8080 \
    OPENDLP_STATIC=/app/frontend \
    OPENDLP_DATA_DIR=/app/data \
    OPENDLP_LOG_FORMAT=json
EXPOSE 8080
USER nonroot:nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD ["/app/opendlp", "healthcheck"]
ENTRYPOINT ["/app/opendlp"]
