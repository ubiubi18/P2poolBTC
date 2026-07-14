#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-}"
DEVICE="/dev/zram0"
SYS_BLOCK="/sys/block/zram0"
SIZE_BYTES="${POHW_ZRAM_SIZE_BYTES:-1073741824}"

is_active() {
  swapon --show=NAME --noheadings | tr -d ' ' | grep -Fxq "$DEVICE"
}

start_zram() {
  if is_active; then
    exit 0
  fi

  if [[ ! "$SIZE_BYTES" =~ ^[1-9][0-9]{7,}$ ]]; then
    echo "POHW_ZRAM_SIZE_BYTES must be an integer of at least 10 MB." >&2
    exit 1
  fi

  modprobe zram num_devices=1
  if [[ ! -b "$DEVICE" || ! -d "$SYS_BLOCK" ]]; then
    echo "zram device was not created: $DEVICE" >&2
    exit 1
  fi

  if [[ "$(<"$SYS_BLOCK/disksize")" != "0" ]]; then
    echo 1 > "$SYS_BLOCK/reset"
  fi
  if grep -qw lz4 "$SYS_BLOCK/comp_algorithm"; then
    echo lz4 > "$SYS_BLOCK/comp_algorithm"
  fi
  echo "$SIZE_BYTES" > "$SYS_BLOCK/disksize"
  mkswap --label pohw-zram "$DEVICE" >/dev/null
  swapon --priority 100 "$DEVICE"
}

stop_zram() {
  if is_active; then
    swapoff "$DEVICE"
  fi
  if [[ -e "$SYS_BLOCK/reset" ]]; then
    echo 1 > "$SYS_BLOCK/reset"
  fi
}

case "$ACTION" in
  start)
    start_zram
    ;;
  stop)
    stop_zram
    ;;
  *)
    echo "Usage: pohw-zram {start|stop}" >&2
    exit 2
    ;;
esac
