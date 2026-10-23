#!/bin/sh
set -eu

pkill -f interceptor 2>/dev/null || true
echo "Interceptor stopped."
