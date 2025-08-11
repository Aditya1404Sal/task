#!/bin/bash
set -e

# Mounting debugfs and tracefs inside container
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || echo "debugfs mount failed (may already exist)"
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || echo "tracefs mount failed (may already exist)"

# Verify mounts worked
if [ -d "/sys/kernel/tracing/events" ]; then
    echo "tracefs successfully mounted"
else
    echo "tracefs mount verification failed"
    exit 1
fi

# Execute the main application
exec "$@"
