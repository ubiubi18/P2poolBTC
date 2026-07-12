#!/bin/sh
set -eu

FORCED_COMMAND='/usr/bin/rrsync -wo /var/lib/idena-return-inbox'
GUARD='/usr/local/libexec/idena-return-rrsync-guard.py'

if [ "$#" -eq 2 ] && [ "$1" = "-c" ] && [ "$2" = "$FORCED_COMMAND" ]; then
  case "${SSH_ORIGINAL_COMMAND:-}" in
    idena-return-capacity)
      exec "$GUARD" capacity
      ;;
    rsync\ --server\ *)
      exec "$GUARD" transfer
      ;;
  esac
fi

printf '%s\n' 'This account only accepts write-only Idena return transfers.' >&2
exit 1
