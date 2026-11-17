# mini-siem

Un SIEM pequeño escrito en Go. Recibe eventos de seguridad (logins SSH, peticiones nginx, eventos de aplicación), los procesa en paralelo y detecta patrones sospechosos: fuerza bruta, cuentas posiblemente comprometidas y escaneos de rutas. Las alertas se guardan en PostgreSQL, llegan por Telegram y se ven en un panel web.

Es un proyecto de aprendizaje y portafolio: se construye por fases, desde un servidor HTTP mínimo hasta un sistema desplegado que recibe eventos reales de un servidor Linux.

> **Estado:** fases 0 a 5 completas (ingesta, cola concurrente, detección, persistencia, notificaciones y panel). El empaquetado, el agente y el despliegue están en desarrollo. Ver [Hoja de ruta](#hoja-de-ruta).

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
    W1 & W2 & W3 & W4 -->|evalúa| D["Detectores<br/>fuerza bruta · compromiso · escaneo"]
    D -->|alerta| F[("PostgreSQL<br/>alerts")]
    D -->|"encola (no bloquea)"| N["Notificador<br/>reintentos"]
    N --> T[Telegram]
    E & F -->|"GET /events · /alerts · /stats"| P["Panel web<br/>GET /"]
```

El recorrido de un evento:

1. **Ingesta.** Un cliente envía el evento en JSON a `POST /events`. La API rechaza los cuerpos mayores de 1 MB, el JSON mal formado, los campos desconocidos y las IPs inválidas.
2. **Cola.** Si el evento es válido, entra en una cola en memoria y la API responde `202 Accepted` de inmediato, sin esperar a la base de datos. Si la cola está llena, responde `503` con `Retry-After: 1` (contrapresión) para no saturar el sistema.
3. **Procesamiento.** Cuatro workers concurrentes toman eventos de la cola. Cada uno guarda el evento en PostgreSQL y luego lo pasa por cada una de las reglas de detección.
4. **Detección.** Cada regla lleva, por IP, una ventana deslizante con los eventos que le interesan. Si una IP cruza el umbral, se genera una alerta y se guarda. Un mismo evento puede disparar varias reglas.
5. **Notificación.** La alerta guardada pasa a un notificador con su propia cola y goroutine, que la envía a Telegram con timeout y reintentos. El worker no espera: si Telegram está lento o caído, los eventos se siguen procesando.
6. **Consulta.** El panel web (`GET /`) y la API (`GET /events`, `GET /alerts`, `GET /stats/top-ips`) leen de la base de datos, así que los datos sobreviven a los reinicios.

Al recibir `Ctrl+C` o `SIGTERM`, el servidor se apaga en orden: deja de aceptar peticiones, los workers terminan los eventos de la cola, el notificador envía las alertas pendientes (hasta 10 s) y por último se cierra la conexión con la base.

### Reglas de detección

| Regla | Qué detecta | Se dispara con (por defecto) |
|---|---|---|
| `brute_force` | Ataque de fuerza bruta | 5 `login_failed` desde una IP en 1 minuto. No se repite en 5 minutos |
| `possible_compromise` | El ataque funcionó: posible cuenta comprometida | Un `login_success` desde una IP con 5 o más `login_failed` en los últimos 10 minutos |
| `http_404_scan` | Escaneo de rutas (`/wp-admin`, `/.env`…) | 20 eventos `nginx` de tipo `http_404` desde una IP en 1 minuto. No se repite en 10 minutos |

- Las ventanas usan el `timestamp` del evento (cuándo ocurrió), no el momento en que llegó al servidor.
- Cada IP se evalúa por separado.
- El enfriamiento evita una avalancha de alertas durante un ataque largo. `possible_compromise` no lo necesita: después de un login exitoso la racha de fallos se reinicia.
- `brute_force` y `http_404_scan` son dos configuraciones de la misma regla genérica de umbral (`detector.Threshold`), así que agregar otra regla de "N eventos en T segundos" cuesta unas pocas líneas.

Todos los umbrales, ventanas y enfriamientos se configuran con variables de entorno (ver [Configuración](#configuración)).

**Tipos de evento que entienden las reglas:** `login_failed` y `login_success` (cualquier `source`), y `http_404` (con `source: "nginx"`). Se aceptan otros tipos: se guardan y se ven en el panel, pero ninguna regla los evalúa.

---

## Inicio rápido

**Requisitos:** Go 1.27 o superior y Docker.

```bash
git clone https://github.com/williamfloress/mini-siem.git
cd mini-siem

# 1. Levantar PostgreSQL (puerto 5433 del host)
docker compose up -d

# 2. Crear tu configuración local (ya trae la DATABASE_URL del docker compose)
cp .env.example .env

# 3. Arrancar el servidor (las migraciones se aplican solas)
go run ./cmd/server
```

El panel queda en **http://localhost:8080/** y se actualiza cada 5 segundos.

En PowerShell, el paso 2 es `Copy-Item .env.example .env`.

Sin `DATABASE_URL` (vacía en `.env` o sin `.env`), el servidor arranca en **modo memoria**: funciona igual, pero los datos se pierden al reiniciar. Es útil para probar algo rápido sin Docker.

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

Si ahora esa IP inicia sesión con éxito, salta la alerta más grave, `possible_compromise`:

```bash
curl -s -X POST localhost:8080/events -d '{"timestamp":"2026-11-16T10:00:30Z","source":"ssh","type":"login_success","ip":"203.0.113.7","user":"root"}'
```

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

### `GET /stats/top-ips?limit=N&window=D`

Devuelve las IPs con más eventos en el periodo `window` (por defecto `24h`, máximo `720h`), de la más activa a la menos. `limit` va de 1 a 100 (por defecto 10).

```json
{
  "window": "24h0m0s",
  "since": "2026-11-15T16:09:00Z",
  "ips": [
    { "ip": "192.0.2.77", "events": 25, "failed_logins": 0, "last_seen": "2026-11-16T16:09:02Z" },
    { "ip": "198.51.100.23", "events": 7, "failed_logins": 6, "last_seen": "2026-11-16T16:08:58Z" }
  ]
}
```

Se resuelve con un `GROUP BY ip` en PostgreSQL, sin traer los eventos a Go.

### `GET /`

El panel web: alertas, eventos recientes y top IPs, con refresco automático.

### `GET /healthz`

Responde `{"status":"ok"}` mientras el proceso está vivo.

En los endpoints `GET`, un `limit` fuera de rango devuelve `400`. Un fallo de la base de datos devuelve `500` con un mensaje genérico; el detalle queda en el log del servidor.

---

## Configuración

Toda la configuración se lee de variables de entorno ([12-factor](https://12factor.net/config)). Al arrancar, el servidor lee `.env` si existe (con [godotenv](https://github.com/joho/godotenv)); copia [`.env.example`](.env.example) a `.env` y ajústalo. Las variables definidas en el entorno tienen prioridad sobre `.env`, así que en Docker o en producción se configura igual que siempre.

| Variable | Por defecto | Descripción |
|---|---|---|
| `DATABASE_URL` | *(vacía)* | Conexión a PostgreSQL. Vacía = modo memoria. Admite `?pool_max_conns=N` |
| `PORT` | `8080` | Puerto HTTP |
| `BRUTEFORCE_THRESHOLD` | `5` | Logins fallidos para alertar |
| `BRUTEFORCE_WINDOW` | `1m` | Ventana de conteo (`30s`, `1m`, `2h`…) |
| `BRUTEFORCE_COOLDOWN` | `5m` | Enfriamiento entre alertas de la misma IP |
| `COMPROMISE_THRESHOLD` | `5` | Fallos previos para considerar sospechoso un login exitoso |
| `COMPROMISE_WINDOW` | `10m` | Cuánto tiempo atrás se miran esos fallos |
| `SCAN_THRESHOLD` | `20` | Respuestas 404 para alertar de escaneo |
| `SCAN_WINDOW` | `1m` | Ventana de conteo del escaneo |
| `SCAN_COOLDOWN` | `10m` | Enfriamiento entre alertas de escaneo de la misma IP |
| `TELEGRAM_BOT_TOKEN` | *(vacía)* | Token del bot. Vacía = sin notificaciones externas |
| `TELEGRAM_CHAT_ID` | *(vacía)* | Chat que recibe las alertas. Va junto con el token |

Si hay valores inválidos, el servidor no arranca y muestra todos los errores juntos.

---

## Notificaciones por Telegram

1. En Telegram, habla con [@BotFather](https://t.me/BotFather), envía `/newbot` y sigue los pasos. Al final te da el **token** (algo como `123456789:AA…`).
2. Abre el chat con tu bot nuevo y envíale cualquier mensaje (un bot no puede escribirte si tú no le escribiste antes).
3. Abre `https://api.telegram.org/bot<TOKEN>/getUpdates` en el navegador. En la respuesta, `"chat":{"id":…}` es tu **chat ID**.
4. Pon las dos variables en tu `.env` y arranca el servidor con `go run ./cmd/server`:

```dotenv
TELEGRAM_BOT_TOKEN=123456789:AA...
TELEGRAM_CHAT_ID=987654321
```

Cada alerta llega como un mensaje con la regla, la IP, el número de eventos y la hora. El envío funciona así:

- **No bloquea:** los workers dejan la alerta en una cola de 100 y siguen procesando eventos. Si la cola se llena, la alerta se descarta (queda en el log y en el panel).
- **Reintentos:** hasta 4 intentos con espera creciente (1 s, 2 s, 4 s) y 10 s de timeout por intento, para caídas de red, errores 5xx o `429` (límite de mensajes).
- **Errores permanentes:** un token o chat incorrecto (`401`, `400`) no se reintenta.
- **El token no aparece en los logs:** los errores de red de Go incluyen la URL, y la URL lleva el token, así que se descarta antes de registrar el error.

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
  detector/            reglas de detección y ventana deslizante
  event/               modelo de evento y validación
  notify/              notificador con reintentos y cliente de Telegram
  pipeline/            cola con buffer y workers concurrentes
  store/               almacenamiento: PostgreSQL y memoria
  web/                 panel web (HTML embebido en el binario)
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
- **Notificar sin frenar.** Telegram puede tardar o caerse; por eso el envío va en su propia goroutine con su propia cola, y el worker solo encola.
- **Reglas como lista.** El pipeline recibe un `[]Detector`. Agregar una regla es implementar `Check(evento) *Alert` y sumarla a la lista en `main.go`.
- **Panel sin dependencias ni HTML inyectado.** Es un solo archivo HTML que usa `fetch`. Todo el contenido de los eventos se inserta con `textContent`, nunca como HTML, porque lo escribe quien envía el evento (un atacante incluido). La página también envía una `Content-Security-Policy` que bloquea scripts de otros orígenes.

---

## Limitaciones conocidas

- Si la base de datos falla después de responder `202`, el evento se pierde (queda registrado en el log). Las soluciones posibles son reintentos en el worker o una cola persistente.
- `POST /events` no tiene autenticación: cualquiera puede enviar eventos falsos. Está planificado para la fase 6.
- El panel y los endpoints de lectura no tienen autenticación: cualquiera que llegue al puerto ve los eventos. No lo expongas a internet hasta la fase 6.
- El estado de los detectores (ventanas y enfriamientos) vive en memoria. Al reiniciar se pierde, aunque los eventos sigan en la base.
- Los mapas de los detectores crecen con cada IP nueva y no se limpian del todo.
- La cola de notificaciones vive en memoria: si el proceso muere de golpe, las alertas pendientes no se envían (sí quedan guardadas en la base).
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
| 5 | Notificaciones por Telegram, panel web, estadísticas, reglas de compromiso y escaneo | ✅ |
| 6 | Dockerfile, CI con GitHub Actions, API key, rate limiting, `/readyz` y `/metrics` | 🚧 |
| 7 | Agente que lee `/var/log/auth.log` en tiempo real y despliegue en un VPS con HTTPS | ⏳ |
| 8 | Benchmark de rendimiento y caso de estudio | ⏳ |

El producto final: un agente en un servidor Linux envía cada intento de login SSH al SIEM; el SIEM detecta los ataques, avisa por Telegram o correo y los muestra en un dashboard público.

---

## Tecnologías

Go (biblioteca estándar: `net/http`, `log/slog`, `embed`) · PostgreSQL 17 · [pgx](https://github.com/jackc/pgx) · [goose](https://github.com/pressly/goose) · Docker Compose
