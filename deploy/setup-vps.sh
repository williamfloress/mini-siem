#!/usr/bin/env bash
# Prepara un VPS Ubuntu 22.04+ o Debian 12+ recién creado para el SIEM. Se ejecuta una
# vez, con sudo (o como root), desde una copia de la carpeta deploy/:
#
#   scp -r deploy ubuntu@VPS:~/mini-siem-deploy
#   ssh ubuntu@VPS "sudo bash ~/mini-siem-deploy/setup-vps.sh"
#
# La guía completa, con la creación del servidor, está en deploy/README.md.
# Se puede repetir: no pisa .env ni agent.env si ya existen.
# No toca la configuración de SSH: eso se hace a mano (ver deploy/README.md), porque un
# error ahí te deja fuera del servidor (en Oracle Cloud, además, ya viene sin contraseñas).
set -euo pipefail

DEPLOY_USER=${DEPLOY_USER:-deploy}
APP_DIR=/opt/mini-siem
SRC=$(cd "$(dirname "$0")" && pwd)

if [[ $EUID -ne 0 ]]; then
  echo "ejecútalo como root" >&2
  exit 1
fi

echo "== paquetes"
apt-get update -q
# rsyslog: las imágenes recientes de Debian solo usan journald y no crean /var/log/auth.log.
# unattended-upgrades: parches de seguridad del sistema sin intervención.
apt-get install -y -q ca-certificates curl ufw rsyslog unattended-upgrades
systemctl enable --now rsyslog

if ! command -v docker >/dev/null; then
  echo "== Docker"
  curl -fsSL https://get.docker.com | sh
fi

echo "== usuario $DEPLOY_USER"
if ! id "$DEPLOY_USER" >/dev/null 2>&1; then
  adduser --disabled-password --gecos "" "$DEPLOY_USER"
fi
# Ojo: el grupo docker equivale a root. Es el usuario que usa GitHub Actions para
# desplegar; su clave SSH es tan sensible como la de root.
usermod -aG docker "$DEPLOY_USER"
install -d -m 700 -o "$DEPLOY_USER" -g "$DEPLOY_USER" "/home/$DEPLOY_USER/.ssh"
touch "/home/$DEPLOY_USER/.ssh/authorized_keys"
chown "$DEPLOY_USER:$DEPLOY_USER" "/home/$DEPLOY_USER/.ssh/authorized_keys"
chmod 600 "/home/$DEPLOY_USER/.ssh/authorized_keys"

echo "== $APP_DIR"
# 755: el agente (otro usuario) tiene que poder ejecutar bin/mini-siem-agent.
install -d -m 755 -o "$DEPLOY_USER" -g "$DEPLOY_USER" "$APP_DIR" "$APP_DIR/bin"
install -d -m 700 -o "$DEPLOY_USER" -g "$DEPLOY_USER" /var/backups/mini-siem
install -m 644 -o "$DEPLOY_USER" -g "$DEPLOY_USER" "$SRC/compose.yml" "$SRC/Caddyfile" "$APP_DIR/"
install -m 755 -o "$DEPLOY_USER" -g "$DEPLOY_USER" "$SRC/deploy.sh" "$SRC/backup.sh" "$APP_DIR/"
if [[ ! -f $APP_DIR/.env ]]; then
  install -m 600 -o "$DEPLOY_USER" -g "$DEPLOY_USER" "$SRC/.env.example" "$APP_DIR/.env"
fi

echo "== agente y copias de seguridad (systemd)"
install -d -m 755 /etc/mini-siem
if [[ ! -f /etc/mini-siem/agent.env ]]; then
  install -m 600 "$SRC/agent.env.example" /etc/mini-siem/agent.env
fi
install -m 644 "$SRC"/systemd/mini-siem-* /etc/systemd/system/
sed -i "s/^User=.*/User=$DEPLOY_USER/" /etc/systemd/system/mini-siem-backup.service
systemctl daemon-reload
systemctl enable --now mini-siem-backup.timer

# deploy.sh reinicia el agente tras actualizar el binario. Solo ese comando, nada más.
SUDOERS=/etc/sudoers.d/mini-siem
echo "$DEPLOY_USER ALL=(root) NOPASSWD: /usr/bin/systemctl restart mini-siem-agent.service" >"$SUDOERS.tmp"
chmod 440 "$SUDOERS.tmp"
visudo -cf "$SUDOERS.tmp" >/dev/null
mv "$SUDOERS.tmp" "$SUDOERS"

echo "== firewall"
# Docker publica 80 y 443 por su cuenta (se salta ufw), pero así queda explícito qué
# se espera abierto. Postgres y la app no se publican.
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp
ufw --force enable

cat <<EOF

Listo. Faltan los pasos manuales (detalle en deploy/README.md):
  1. Completa $APP_DIR/.env y /etc/mini-siem/agent.env.
  2. Añade la clave pública de GitHub Actions a /home/$DEPLOY_USER/.ssh/authorized_keys.
  3. Configura los secretos del repo y ejecuta el workflow Deploy.
  4. systemctl enable --now mini-siem-agent
EOF
