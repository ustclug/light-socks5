#! /bin/sh

DEFAULT_LOG_PATH="/var/log/ganted/access.log"

log_path="${GANTED_ACCESS_LOG:-$DEFAULT_LOG_PATH}"
log_dir=$(dirname "$log_path")

cd "$log_dir" || exit 1

cat "$log_path" > archive.log
truncate -s 0 "$log_path"

/app/ganted2radius archive.log
