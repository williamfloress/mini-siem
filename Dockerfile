# syntax=docker/dockerfile:1

# --- Etapa 1: compilar ---
FROM golang:1.27.4-alpine AS build
WORKDIR /src

# Primero solo go.mod y go.sum: mientras no cambien las dependencias, Docker
# reutiliza esta capa y no las vuelve a descargar en cada build.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
# CGO_ENABLED=0: binario estático, sin depender de la libc de la imagen final.
# -trimpath quita las rutas locales del binario; -s -w quita los símbolos de depuración.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mini-siem ./cmd/server

# --- Etapa 2: imagen final ---
# distroless/static: sin shell, sin gestor de paquetes, solo certificados CA y zona horaria.
# Si alguien explota el proceso, no tiene herramientas con las que seguir.
FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/mini-siem /mini-siem

# nonroot = UID 65532. El proceso no corre como root dentro del contenedor.
USER nonroot:nonroot
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/mini-siem", "healthcheck"]

ENTRYPOINT ["/mini-siem"]
