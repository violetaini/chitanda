#!/bin/sh
set -eu

source_dir=/www/server/panel/vhost/cert/chitanda.org
target_dir=/etc/myxray/tls

test -s "$source_dir/fullchain.pem"
test -s "$source_dir/privkey.pem"

changed=0
for name in fullchain.pem privkey.pem; do
    if ! cmp -s "$source_dir/$name" "$target_dir/$name"; then
        install -o root -g myxray -m 0640 "$source_dir/$name" "$target_dir/$name"
        changed=1
    fi
done

if [ "$changed" -eq 1 ]; then
    systemctl try-restart myxray-server.service
fi
