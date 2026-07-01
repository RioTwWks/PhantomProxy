#!/usr/bin/env bash
# Установка PhantomProxy как systemd-сервис (одна команда).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_NAME="${PHANTOM_SERVICE_NAME:-phantom-proxy}"
INSTALL_DIR="${PHANTOM_INSTALL_DIR:-/opt/phantomproxy}"
CONFIG_DIR="${PHANTOM_CONFIG_DIR:-/etc/phantomproxy}"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
SKIP_BUILD=0

for arg in "$@"; do
  case "$arg" in
    --no-build|--skip-build) SKIP_BUILD=1 ;;
    -h|--help)
      echo "Использование: sudo bash deploy/install.sh [--no-build]"
      echo "  --no-build  не собирать бинарь (ожидается готовый telegram-proxy в корне репо)"
      exit 0
      ;;
  esac
done
[[ "${PHANTOM_SKIP_BUILD:-}" == "1" ]] && SKIP_BUILD=1

if [[ "${EUID:-0}" -ne 0 ]]; then
  echo "Запусти: sudo bash $0" >&2
  exit 1
fi

build_proxy() {
  export GOTOOLCHAIN=local
  if command -v go &>/dev/null; then
    make -C "$ROOT" build
    return
  fi
  if [[ -n "${SUDO_USER:-}" ]] && sudo -u "$SUDO_USER" -H bash -lc 'command -v go >/dev/null'; then
    sudo -u "$SUDO_USER" -H bash -lc "cd '$ROOT' && export GOTOOLCHAIN=local && make build"
    return
  fi
  echo "Go не найден в PATH root. Собери от своего пользователя: make build" >&2
  echo "Затем: PHANTOM_SKIP_BUILD=1 sudo bash deploy/install.sh" >&2
  exit 1
}

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  echo "==> Сборка"
  build_proxy
elif [[ ! -x "$ROOT/telegram-proxy" ]]; then
  echo "Бинарь $ROOT/telegram-proxy не найден. Запусти: make build" >&2
  exit 1
fi

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
