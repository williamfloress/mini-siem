# mini-siem

Un SIEM pequeño escrito en Go. Recibe eventos de seguridad (logins SSH, peticiones nginx, eventos de aplicación), los procesa en paralelo, detecta patrones sospechosos como ataques de fuerza bruta y genera alertas que se guardan en PostgreSQL.

Es un proyecto de aprendizaje y portafolio: se construye por fases, desde un servidor HTTP mínimo hasta un sistema desplegado que recibe eventos reales de un servidor Linux.

> **Estado:** fases 0 a 4 completas (ingesta, cola concurrente, detección y persistencia). Las notificaciones, el dashboard, el agente y el despliegue están en desarrollo. Ver [Hoja de ruta](#hoja-de-ruta).

---

## Cómo funciona

```mermaid
flowchart LR
    A["Fuentes<br/>ssh · nginx · app"] -->|"POST /events"| B["API HTTP<br/>validación"]
    B -->|"202 Accepted"| A
    B -->|encola| C[("Cola<br/>buffer 1000")]
    C --> W1[worker 1]
    C --> W2[worker 2]
    C --> W3[worker 3]
    C --> W4[worker 4]
    W1 & W2 & W3 & W4 -->|guarda| E[("PostgreSQL<br/>events")]
    W1 & W2 & W3 & W4 -->|evalúa| D["Detector<br/>fuerza bruta"]
    D -->|alerta| F[("PostgreSQL<br/>alerts")]
    E -->|"GET /events"| U[Usuario]
    F -->|"GET /alerts"| U
```

El recorrido de un evento:

1. **Ingesta.** Un cliente envía el evento en JSON a `POST /events`. La API rechaza los cuerpos mayores de 1 MB, el JSON mal formado, los campos desconocidos y las IPs inválidas.
2. **Cola.** Si el evento es válido, entra en una cola en memoria y la API responde `202 Accepted` de inmediato, sin esperar a la base de datos. Si la cola está llena, responde `503` con `Retry-After: 1` (contrapresión) para no saturar el sistema.
3. **Procesamiento.** Cuatro workers concurrentes toman eventos de la cola. Cada uno guarda el evento en PostgreSQL y luego lo pasa por el detector.
4. **Detección.** El detector lleva, para cada IP, una ventana deslizante con sus logins fallidos. Cuando una IP supera el umbral dentro de la ventana, se genera una alerta.
5. **Consulta.** `GET /events` y `GET /alerts` devuelven los registros más recientes directamente desde la base de datos, así que los datos sobreviven a los reinicios.

Al recibir `Ctrl+C` o `SIGTERM`, el servidor se apaga en orden: deja de aceptar peticiones, los workers terminan los eventos que quedan en la cola y por último se cierra la conexión con la base.

### Regla de fuerza bruta

| Parámetro | Por defecto | Significado |
|---|---|---|
| Umbral | 5 | Logins fallidos necesarios para alertar |
| Ventana | 1 minuto | Periodo en el que se cuentan los intentos |
| Enfriamiento | 5 minutos | Tiempo sin repetir la alerta para la misma IP |

- Solo cuentan los eventos con `type: "login_failed"`.
- La ventana usa el `timestamp` del evento (cuándo ocurrió), no el momento en que llegó al servidor.
- Cada IP se evalúa por separado.
- El enfriamiento evita una avalancha de alertas durante un ataque largo.

Los tres parámetros se configuran con variables de entorno (ver [Configuración](#configuración)).

---

## Inicio rápido

**Requisitos:** Go 1.27 o superior y Docker.

```bash
git clone https://github.com/williamfloress/mini-siem.git
cd mini-siem

# 1. Levantar PostgreSQL (puerto 5433 del host)
docker compose up -d

# 2. Arrancar el servidor (las migraciones se aplican solas)
export DATABASE_URL="postgres://siem:siem@localhost:5433/siem?sslmode=disable"
go run ./cmd/server
```

En PowerShell, la variable se define así:

```powershell
$env:DATABASE_URL = "postgres://siem:siem@localhost:5433/siem?sslmode=disable"
go run ./cmd/server
```

Sin `DATABASE_URL`, el servidor arranca en **modo memoria**: funciona igual, pero los datos se pierden al reiniciar. Es útil para probar algo rápido sin Docker.

### Simular un ataque

Envía seis logins fallidos desde la misma IP:

```bash
for i in 1 2 3 4 5 6; do
  curl -s -X POST localhost:8080/events -d "{
    \"timestamp\": \"2026-11-16T10:00:0${i}Z\",
    \"source\": \"ssh\",
    \"type\": \"login_failed\",
    \"ip\": \"203.0.113.7\",
    \"user\": \"root\"
  }"
done

curl -s localhost:8080/alerts
```

```json
[
  {
    "id": 1,
    "rule": "brute_force",
    "ip": "203.0.113.7",
    "count": 5,
    "triggered_at": "2026-11-16T10:00:05Z",
    "message": "5 logins fallidos desde 203.0.113.7 en 1m0s"
  }
]
```

La alerta salta en el quinto intento. El sexto cae dentro del enfriamiento y no genera otra.

---

## API

### `POST /events`

Recibe un evento y lo encola para procesarlo.

| Campo | Tipo | Requerido | Descripción |
|---|---|---|---|
| `timestamp` | string (RFC 3339) | sí | Cuándo ocurrió el evento |
| `source` | string | sí | `ssh`, `nginx` o `app` |
| `type` | string | sí | Tipo de evento, por ejemplo `login_failed` |
| `ip` | string | sí | IP de origen, IPv4 o IPv6 |
| `user` | string | no | Usuario involucrado |
| `message` | string | no | Texto libre, por ejemplo la línea de log original |

El servidor asigna `id` y `received_at`. Si el JSON trae cualquier otro campo, se rechaza.

| Código | Cuándo |
|---|---|
| `202` | Evento aceptado y encolado |
| `400` | JSON inválido, campos desconocidos o cuerpo mayor de 1 MB |
| `422` | Falta un campo requerido, el `source` no es válido o la IP es inválida |
| `503` | Cola llena; reintentar (`Retry-After: 1`) |

### `GET /events?limit=N`

Devuelve los últimos `N` eventos (por defecto 50, máximo 500), ordenados del más antiguo al más reciente.

### `GET /alerts?limit=N`

Devuelve las últimas `N` alertas, con los mismos límites.

### `GET /healthz`

Responde `{"status":"ok"}` mientras el proceso está vivo.

En los endpoints `GET`, un `limit` fuera de rango devuelve `400`. Un fallo de la base de datos devuelve `500` con un mensaje genérico; el detalle queda en el log del servidor.

---

## Configuración

Toda la configuración se lee de variables de entorno ([12-factor](https://12factor.net/config)). Hay un ejemplo en [`.env.example`](.env.example).

| Variable | Por defecto | Descripción |
|---|---|---|
| `DATABASE_URL` | *(vacía)* | Conexión a PostgreSQL. Vacía = modo memoria. Admite `?pool_max_conns=N` |
| `PORT` | `8080` | Puerto HTTP |
| `BRUTEFORCE_THRESHOLD` | `5` | Logins fallidos para alertar |
| `BRUTEFORCE_WINDOW` | `1m` | Ventana de conteo (`30s`, `1m`, `2h`…) |
| `BRUTEFORCE_COOLDOWN` | `5m` | Enfriamiento entre alertas de la misma IP |

Si hay valores inválidos, el servidor no arranca y muestra todos los errores juntos.

---

## Base de datos

El esquema se gestiona con migraciones versionadas de [goose](https://github.com/pressly/goose), en [`internal/db/migrations/`](internal/db/migrations/). Van embebidas en el binario y se aplican automáticamente al arrancar. También se pueden correr a mano:

```bash
goose -dir internal/db/migrations postgres "$DATABASE_URL" status
```

| Tabla | Índices | Para qué |
|---|---|---|
| `events` | `(occurred_at)` | Listar los eventos más recientes |
| | `(ip, occurred_at)` | Consultas por IP en un rango de tiempo (reglas y estadísticas) |
| `alerts` | `(triggered_at)` | Listar las alertas más recientes |

Las IPs se guardan con el tipo `INET` de PostgreSQL, así que la base también rechaza las direcciones mal formadas.

---

## Tests

```bash
go test ./...
```

Los tests unitarios (detector y configuración) no necesitan nada externo. Los de integración prueban los stores contra un PostgreSQL real y se saltan si no se define `TEST_DATABASE_URL`:

```bash
docker compose up -d
TEST_DATABASE_URL="postgres://siem:siem@localhost:5433/siem_test?sslmode=disable" go test ./...
```

Usan la base `siem_test`, que se crea con el contenedor, porque vacían las tablas al empezar.

---

## Estructura

```
cmd/server/            punto de entrada: configuración, arranque y apagado ordenado
internal/
  api/                 handlers HTTP y validación de parámetros
  config/              lectura de variables de entorno
  db/                  pool de conexiones y migraciones (goose)
  detector/            reglas de detección (fuerza bruta)
  event/               modelo de evento y validación
  pipeline/            cola con buffer y workers concurrentes
  store/               almacenamiento: PostgreSQL y memoria
docker/postgres/       script de inicialización de la base
```

---

## Decisiones de diseño

- **Respuesta asíncrona (`202`).** La API no espera a la base de datos. Así absorbe picos de tráfico, y si la cola se llena avisa con `503` en lugar de degradarse en silencio.
- **Interfaces pequeñas entre capas.** El pipeline y la API dependen de interfaces (`Store`, `AlertSink`, `EventLister`), no de PostgreSQL. Por eso el mismo código funciona con el store en memoria o con la base, y se puede probar por partes.
- **Errores que se propagan.** Escribir en una base de datos puede fallar, así que cada store devuelve `error`. La API responde `500` sin revelar detalles internos, y el worker registra el fallo y sigue con el siguiente evento.
- **Timeouts en cada escritura.** Si la base se cuelga, ningún worker queda bloqueado más de 5 segundos.
- **Migraciones dentro del binario.** Desplegar es copiar un solo ejecutable; el esquema se actualiza solo al arrancar.
- **La ventana usa el tiempo del evento**, no el de llegada. Así la detección funciona igual si los eventos se reenvían con retraso.

---

## Limitaciones conocidas

- Si la base de datos falla después de responder `202`, el evento se pierde (queda registrado en el log). Las soluciones posibles son reintentos en el worker o una cola persistente.
- `POST /events` no tiene autenticación: cualquiera puede enviar eventos falsos. Está planificado para la fase 6.
- El estado del detector (ventanas y enfriamientos) vive en memoria. Al reiniciar se pierde, aunque los eventos sigan en la base.
- El mapa de intentos del detector crece con cada IP nueva y nunca se limpia.
- Con varios workers, los eventos pueden procesarse algo desordenados, y la ventana puede ser ligeramente imprecisa.

---

## Hoja de ruta

| Fase | Contenido | Estado |
|---|---|---|
| 0 | Entorno, estructura del proyecto, `/healthz` | ✅ |
| 1 | Ingesta con validación y almacén en memoria | ✅ |
| 2 | Cola con buffer, workers concurrentes, contrapresión, apagado ordenado | ✅ |
| 3 | Detector de fuerza bruta con ventana deslizante, `GET /alerts` | ✅ |
| 4 | PostgreSQL, migraciones, pool de conexiones, configuración por entorno | ✅ |
| 5 | Notificaciones (Telegram/email), dashboard web, estadísticas, más reglas de detección | 🚧 |
| 6 | Dockerfile, CI con GitHub Actions, API key, rate limiting, `/readyz` y `/metrics` | ⏳ |
| 7 | Agente que lee `/var/log/auth.log` en tiempo real y despliegue en un VPS con HTTPS | ⏳ |
| 8 | Benchmark de rendimiento y caso de estudio | ⏳ |

El producto final: un agente en un servidor Linux envía cada intento de login SSH al SIEM; el SIEM detecta los ataques, avisa por Telegram o correo y los muestra en un dashboard público.

---

## Tecnologías

Go (biblioteca estándar: `net/http`, `log/slog`, `embed`) · PostgreSQL 17 · [pgx](https://github.com/jackc/pgx) · [goose](https://github.com/pressly/goose) · Docker Compose
