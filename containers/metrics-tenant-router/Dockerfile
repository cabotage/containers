FROM golang:1.27.2-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 go build -o /out/metrics-tenant-router .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/metrics-tenant-router /metrics-tenant-router
USER nonroot:nonroot
ENTRYPOINT ["/metrics-tenant-router"]
