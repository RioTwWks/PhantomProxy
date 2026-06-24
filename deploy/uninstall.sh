#!/usr/bin/env bash
# Удаление PhantomProxy (одна команда).
set -euo pipefail

SERVICE_NAME="${PHANTOM_SERVICE_NAME:-phantom-proxy}"
INSTALL_DIR="${PHANTOM_INSTALL_DIR:-/opt/phantomproxy}"
CONFIG_DIR="${PHANTOM_CONFIG_DIR:-/etc/phantomproxy}"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
PURGE=0
DOCKER=0

usage() {
  cat <<EOF
Использование: sudo bash uninstall.sh [опции]

  --purge     Удалить бинарник, конфиг и каталоги
  --docker    Остановить docker compose (вместо systemd)
  -h, --help  Справка

Примеры:
  sudo bash deploy/uninstall.sh
  sudo bash deploy/uninstall.sh --purge
  sudo bash deploy/uninstall.sh --docker
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge) PURGE=1; shift ;;
    --docker) DOCKER=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Неизвестный аргумент: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ "$DOCKER" == "1" ]]; then
  ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  cd "$ROOT"
  if command -v docker &>/dev/null; then
    docker compose down -v --remove-orphans 2>/dev/null || docker-compose down -v --remove-orphans
    echo "Docker Compose остановлен и удалён"
  else
    echo "docker не найден" >&2
    exit 1
  fi
  exit 0
fi

if command -v systemctl &>/dev/null; then
  echo "==> Остановка $SERVICE_NAME"
  systemctl stop "$SERVICE_NAME" 2>/dev/null || true
  systemctl disable "$SERVICE_NAME" 2>/dev/null || true
  rm -f "$UNIT_PATH"
  systemctl daemon-reload
  echo "==> systemd unit удалён"
else
  echo "systemctl не найден, пропуск"
fi

if [[ "$PURGE" == "1" ]]; then
  echo "==> Удаление файлов"
  rm -rf "$INSTALL_DIR" "$CONFIG_DIR"
  echo "Каталоги $INSTALL_DIR и $CONFIG_DIR удалены"
fi

echo ""
echo "Сервис $SERVICE_NAME удалён."
[[ "$PURGE" == "0" ]] && echo "Конфиг и бинарник сохранены. Для полного удаления: sudo bash $0 --purge"
