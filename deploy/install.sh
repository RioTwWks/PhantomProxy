#!/usr/bin/env bash
# Установка PhantomProxy как systemd-сервис (одна команда).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_NAME="${PHANTOM_SERVICE_NAME:-phantom-proxy}"
INSTALL_DIR="${PHANTOM_INSTALL_DIR:-/opt/phantomproxy}"
CONFIG_DIR="${PHANTOM_CONFIG_DIR:-/etc/phantomproxy}"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

if [[ "${EUID:-0}" -ne 0 ]]; then
  echo "Запусти: sudo bash $0" >&2
  exit 1
fi

echo "==> Сборка"
cd "$ROOT"
export GOTOOLCHAIN=local
make build

echo "==> Пользователь phantom"
id phantom &>/dev/null || useradd -r -s /usr/sbin/nologin phantom

echo "==> Установка файлов"
install -d -m 755 "$INSTALL_DIR"
install -d -m 750 "$CONFIG_DIR"
install -m 755 "$ROOT/telegram-proxy" "$INSTALL_DIR/"
if [[ ! -f "$CONFIG_DIR/config.yaml" ]]; then
  install -m 600 "$ROOT/configs/config.yaml" "$CONFIG_DIR/config.yaml"
fi
install -m 755 "$ROOT/deploy/uninstall.sh" "$INSTALL_DIR/uninstall.sh"

echo "==> systemd unit"
sed "s|/opt/phantomproxy|$INSTALL_DIR|g; s|/etc/phantomproxy|$CONFIG_DIR|g; s|phantom-proxy|$SERVICE_NAME|g" \
  "$ROOT/deploy/phantom-proxy.service" > "$UNIT_PATH"

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"

echo ""
echo "Готово. Проверка:"
echo "  systemctl status $SERVICE_NAME"
echo "  curl -s http://127.0.0.1:8081/api/v1/health"
echo ""
echo "Удаление одной командой:"
echo "  sudo bash $INSTALL_DIR/uninstall.sh"
