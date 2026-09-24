FROM python:3.12-slim-bookworm

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000 \
    DATA_DIR=/app/data \
    DEBIAN_FRONTEND=noninteractive

# Linux security tooling so compliance + network scans behave like a real host
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        python3-dev \
        procps \
        iproute2 \
        iptables \
        openssh-server \
        sudo \
        curl \
        ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY docker/systemctl-shim.sh /usr/bin/systemctl
RUN chmod +x /usr/bin/systemctl \
    && mkdir -p /etc/ssh \
    && if [ -f /etc/ssh/sshd_config ]; then \
        sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config; \
        sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config; \
        grep -q '^PermitRootLogin no' /etc/ssh/sshd_config || echo 'PermitRootLogin no' >> /etc/ssh/sshd_config; \
        grep -q '^PasswordAuthentication no' /etc/ssh/sshd_config || echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config; \
       fi \
    && chmod 644 /etc/passwd \
    && chmod 640 /etc/shadow || true

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY . .
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
    && mkdir -p /app/data

EXPOSE 5000 80

ENTRYPOINT ["/entrypoint.sh"]
