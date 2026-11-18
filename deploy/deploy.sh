#!/usr/bin/env bash
# Actualiza el SIEM a una imagen nueva. Lo ejecuta GitHub Actions por SSH, en el VPS:
#
#   /opt/mini-siem/deploy.sh <tag>      # tag = SHA del commit (o "latest")
#
# Si la app nueva no llega a estar sana, vuelve a la versión anterior.
set -euo pipefail

TAG=${1:?uso: deploy.sh <tag>}
if [[ ! $TAG =~ ^([0-9a-f]{7,40}|latest)$ ]]; then
  echo "tag inválido: $TAG" >&2
  exit 1
fi

cd "$(dirname "$0")"

set_tag() {
  if grep -q '^IMAGE_TAG=' .env; then
    sed -i "s/^IMAGE_TAG=.*/IMAGE_TAG=$1/" .env
  else
    echo "IMAGE_TAG=$1" >>.env
  fi
}

CURRENT=$(sed -n 's/^IMAGE_TAG=//p' .env)
echo "desplegando $TAG (actual: ${CURRENT:-latest})"

# El tag nuevo se pasa por el entorno (tiene prioridad sobre .env) y solo se guarda en
# .env cuando la versión nueva está sana. Así, si algo falla, .env sigue apuntando a la
# versión que funciona y un "docker compose up" manual no levanta la rota.
IMAGE_TAG=$TAG docker compose pull --quiet

# --wait espera a que la app pase su HEALTHCHECK (y Postgres el suyo).
if ! IMAGE_TAG=$TAG docker compose up -d --wait --wait-timeout 120 --remove-orphans; then
  echo "la versión $TAG no arrancó bien; volviendo a ${CURRENT:-latest}" >&2
  docker compose logs --tail 50 app >&2 || true
  docker compose up -d --wait --wait-timeout 120
  exit 1
fi
set_tag "$TAG"

# Agente: el workflow sube el binario nuevo como bin/mini-siem-agent.new. El rename es
# atómico, así que no hace falta parar el agente para reemplazar el ejecutable.
if [[ -f bin/mini-siem-agent.new ]]; then
  chmod 755 bin/mini-siem-agent.new
  mv bin/mini-siem-agent.new bin/mini-siem-agent
  if systemctl is-enabled --quiet mini-siem-agent.service 2>/dev/null; then
    sudo -n /usr/bin/systemctl restart mini-siem-agent.service
    echo "agente actualizado y reiniciado"
  else
    echo "agente actualizado (el servicio aún no está habilitado)"
  fi
fi

# Las imágenes viejas ocupan disco; un VPS pequeño se llena rápido.
docker image prune -f >/dev/null
echo "desplegado $TAG"
