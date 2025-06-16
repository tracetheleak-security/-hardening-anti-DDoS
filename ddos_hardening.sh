#!/bin/bash

### Compatible with Ubuntu/Debian + NGINX

set -e

echo "[+] Start DDoS defense script..."


echo "[+] Configuration of iptables..."

# Empty all
iptables -F
iptables -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow traffic from existing connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Loopback
iptables -A INPUT -i lo -j ACCEPT

# IP spoofing protection
iptables -A INPUT -s 10.0.0.0/8 -j DROP
iptables -A INPUT -s 127.0.0.0/8 ! -i lo -j DROP
iptables -A INPUT -s 169.254.0.0/16 -j DROP
iptables -A INPUT -s 172.16.0.0/12 -j DROP
iptables -A INPUT -s 192.168.0.0/16 -j DROP
iptables -A INPUT -s 224.0.0.0/4 -j DROP
iptables -A INPUT -s 240.0.0.0/5 -j DROP

# Protection SYN Flood
iptables -N DDOS_PROTECT
iptables -A INPUT -p tcp --syn -j DDOS_PROTECT
iptables -A DDOS_PROTECT -m conntrack --ctstate NEW -m limit --limit 15/s --limit-burst 30 -j RETURN
iptables -A DDOS_PROTECT -j DROP

# ICMP limiti
iptables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 4 -j ACCEPT
iptables -A INPUT -p icmp -j DROP

# Access HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# SSH (limitato)
iptables -A INPUT -p tcp --dport 22 -m limit --limit 2/min -j ACCEPT


iptables-save > /etc/iptables/rules.v4

echo "[+] IPTABLES is configured."


echo "[+] Application limit_req on NGINX..."

cat <<EOL >> /etc/nginx/nginx.conf

# DDoS Protection Zone
limit_req_zone \$binary_remote_addr zone=req_limit_per_ip:10m rate=2r/s;
limit_conn_zone \$binary_remote_addr zone=conn_limit_per_ip:10m;

EOL

echo "[!] Remember to modify the 'server {} blocks to use limit_req and limit_conn."
echo "[+] Rate limiting NGINX enabled (configured zone)."

### FAIL2BAN ###
echo "[+] Configuration of Fail2Ban..."

# Create custom filter
cat <<EOF > /etc/fail2ban/filter.d/nginx-http-flood.conf
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*
ignoreregex =
EOF

# Custom jail
cat <<EOF > /etc/fail2ban/jail.d/nginx-ddos.local
[nginx-http-flood]
enabled = true
filter = nginx-http-flood
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 100
findtime = 60
bantime = 3600
action = iptables[name=HTTP, port=http, protocol=tcp]
EOF

# Restart fail2ban
systemctl restart fail2ban

echo "[+] Fail2Ban attivo contro HTTP flood."

###RECOMMENDED PACKAGES ###
echo "[+] Installation of optional monitoring packages..."
apt-get update && apt-get install -y iftop tcpdump net-tools

echo "[✔] DDoS hardening script completed."
