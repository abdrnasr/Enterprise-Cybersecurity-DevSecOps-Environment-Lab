#!/bin/bash
# Usage: reload-nginx.sh <APP_PORT>

set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <APP_PORT>"
  exit 1
fi

APP_PORT="$1"
export APP_PORT

envsubst "\${APP_PORT}" < /etc/nginx/templates/app.conf.template \
  | tee /etc/nginx/sites-available/default >/dev/null

nginx -t
systemctl reload nginx