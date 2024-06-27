#!/bin/sh

set -e

cp /var/run/secrets/cabotage.io/ca.crt /usr/local/share/ca-certificates/
update-ca-certificates

exec /entrypoint.sh "$@"
