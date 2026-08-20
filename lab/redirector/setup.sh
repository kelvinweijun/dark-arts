#!/usr/bin/env bash
# Dark Arts VPS redirector setup (Debian/Ubuntu).
# Usage:
#   ./setup.sh <LAB_HOST_IP> [domain]
#     LAB_HOST_IP  the lab host's reachable IP (Windows host running docker compose)
#     domain       optional: a real domain/DNS record pointing at this VPS for a
#                  Let's Encrypt cert. If omitted, a self-signed cert is generated
#                  and the beacon must be built with -Insecure.
#
# Result: HTTPS :443 on this VPS -> plain HTTP -> LAB_HOST_IP:7443 (the relay).
# Beacon edge: https://<VPS_IP>:443   (build the package with -Insecure unless
#              you supplied a domain with a valid LE cert)
set -euo pipefail

LAB_HOST_IP="${1:?usage: setup.sh <LAB_HOST_IP> [domain]}"
DOMAIN="${2:-}"
FWD_PORT=7443

# The lab host's firewall must allow inbound TCP 7443 from this VPS
# (Windows: New-NetFirewallRule -DisplayName "darkarts-relay" -Direction Inbound
#  -Protocol TCP -LocalPort 7443 -Action Allow).

# Run privileged commands through sudo unless we are already root
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
    if ! $SUDO -n true 2>/dev/null; then
        echo "passwordless sudo is required for $USER (add: echo \"$USER ALL=(ALL) NOPASSWD:ALL\" | sudo tee /etc/sudoers.d/$USER)" >&2
        exit 1
    fi
fi

echo "== installing nginx + certbot =="
if command -v apt-get >/dev/null; then
    $SUDO apt-get update -y
    $SUDO apt-get install -y nginx certbot python3-certbot-nginx curl
elif command -v dnf >/dev/null; then
    $SUDO dnf install -y nginx certbot python3-certbot-nginx curl
else
    echo "unsupported package manager (apt/dnf not found)" >&2
    exit 1
fi

CONF=/etc/nginx/sites-available/darkarts-redirector

if [ -n "$DOMAIN" ]; then
    echo "== requesting Let's Encrypt cert for $DOMAIN =="
    $SUDO certbot certonly --nginx -d "$DOMAIN" --non-interactive --agree-tos \
        --register-unsafely-without-email || true
    sed -e "s/<DOMAIN>/$DOMAIN/g" -e "s/<LAB_HOST_IP>/$LAB_HOST_IP/g" \
        "$(dirname "$0")/nginx-darkarts.conf" | $SUDO tee "$CONF" >/dev/null
else
    echo "== generating self-signed cert =="
    $SUDO mkdir -p /etc/nginx/ssl
    $SUDO openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
        -keyout /etc/nginx/ssl/darkarts.key -out /etc/nginx/ssl/darkarts.crt \
        -subj "/CN=darkarts"
    $SUDO tee "$CONF" >/dev/null <<EOF
server {
    listen 443 ssl;
    server_name _;
    ssl_certificate     /etc/nginx/ssl/darkarts.crt;
    ssl_certificate_key /etc/nginx/ssl/darkarts.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    client_max_body_size 64m;
    location / {
        proxy_pass http://$LAB_HOST_IP:$FWD_PORT;
        proxy_set_header Host \$host;
        proxy_read_timeout 120s;
    }
}
EOF
fi

$SUDO ln -sf "$CONF" /etc/nginx/sites-enabled/darkarts-redirector
$SUDO rm -f /etc/nginx/sites-enabled/default
$SUDO nginx -t
$SUDO systemctl enable nginx
$SUDO systemctl restart nginx

echo "== firewall (ufw) =="
if command -v ufw >/dev/null; then
    $SUDO ufw allow 22/tcp >/dev/null || true
    $SUDO ufw allow 443/tcp >/dev/null || true
    $SUDO ufw --force enable >/dev/null || true
fi

echo
echo "=== DONE ==="
echo "  beacon edge : https://$(hostname -I | awk '{print $1}'):443${DOMAIN:+  ($DOMAIN)}"
echo "  forwards to : $LAB_HOST_IP:$FWD_PORT (lab relay)"
echo "  build:  .\\lab\\make-laptop-package.ps1 -Edge \"https://<VPS_IP>:443\" -Insecure"
echo
echo "Cloud provider (OCI/AWS/GCP/Azure) gotchas:"
echo "  - open TCP 443 (and 80 while certbot runs) in the cloud security list / SG,"
echo "    inbound from 0.0.0.0/0 - VM-level ufw alone is not enough"
echo "  - the lab host must be reachable from this VPS on TCP $FWD_PORT"
echo "    (home NAT: port-forward 7443 on the router to the lab host, or CG-NAT"
echo "    will break it - test with: nc -vz $LAB_HOST_IP $FWD_PORT)"
echo
echo "No nginx? Raw TCP forward alternative (plain HTTP on :7443):"
echo "  socat TCP-LISTEN:7443,fork,reuseaddr TCP:$LAB_HOST_IP:$FWD_PORT"
echo "  iptables -t nat -A PREROUTING -p tcp --dport 7443 -j DNAT --to-destination $LAB_HOST_IP:$FWD_PORT"
