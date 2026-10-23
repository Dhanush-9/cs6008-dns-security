#!/bin/sh
set -eu

pkill -f '[i]nterceptor' 2>/dev/null || true
echo "Interceptor stopped."
