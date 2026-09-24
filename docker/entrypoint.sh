#!/bin/bash
set -euo pipefail

# Realistic Linux host defaults for compliance checks
chmod 644 /etc/passwd 2>/dev/null || true
chmod 640 /etc/shadow 2>/dev/null || true

# Linux firewall (iptables) so Network Policy can detect an active filter
if command -v iptables >/dev/null 2>&1; then
    iptables -F INPUT 2>/dev/null || true
    iptables -P INPUT DROP 2>/dev/null || true
    iptables -P FORWARD DROP 2>/dev/null || true
    iptables -P OUTPUT ACCEPT 2>/dev/null || true
    iptables -A INPUT -i lo -j ACCEPT 2>/dev/null || true
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
        || iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
        || true
    iptables -A INPUT -p tcp --dport 5000 -j ACCEPT 2>/dev/null || true
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
fi

# Authorized listening port (80) so Port Exposure Profile has real Linux sockets
python -m http.server 80 --bind 0.0.0.0 >/tmp/http80.log 2>&1 &

mkdir -p "${DATA_DIR:-/app/data}"

exec python app.py
