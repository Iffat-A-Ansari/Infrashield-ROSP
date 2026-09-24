#!/bin/sh
# Minimal systemctl for containerized Linux so SSH compliance checks can run.
if [ "$1" = "is-active" ]; then
    svc="${2:-}"
    case "$svc" in
        ssh|sshd|ssh.service|sshd.service)
            if command -v pgrep >/dev/null 2>&1 && pgrep -x sshd >/dev/null 2>&1; then
                echo "active"
            else
                echo "inactive"
            fi
            exit 0
            ;;
        *)
            echo "inactive"
            exit 0
            ;;
    esac
fi
exit 0
