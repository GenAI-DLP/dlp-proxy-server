FROM golang:1.26 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /proxy ./cmd/dlp-proxy

FROM gcr.io/distroless/static-debian12
WORKDIR /app
COPY --from=builder /proxy /app/proxy
COPY --from=builder /src/configs /app/configs
# certs/는 이미지에 넣지 않는다 (ca-key.pem 유출 방지).
# docker-compose에서 ./dlp-proxy-server/certs 를 /app/certs 로 읽기 전용 마운트한다.
EXPOSE 8443
ENTRYPOINT ["/app/proxy"]