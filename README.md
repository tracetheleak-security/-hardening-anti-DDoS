# DDos Security

![immagine](https://github.com/user-attachments/assets/49e87d23-3cc3-46fa-93dc-d9a45e105248)


## Set of techniques and configurations designed to strengthen a computer system against DDoS attacks, making it more resilient and able to continue functioning (or degrade in a controlled manner) even under attack..
 
## Attack Recognition and Identification
## will be used to diagnose the type of DDoS (SYN flood, HTTP flood, UDP flood, amplification)
## tools that I will be advanced

## 1. tcpdump for packet analysis
## 2. netstat, ss per socket
## 3. iftop, nload for bandwidth monitoring
```
# Analyzes TCP/IP traffic
sudo tcpdump -i eth0 'tcp or udp or icmp' -n -c 1000

# List the IPs with multiple open connections over HTTP
netstat -ntu | grep :80 | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head

# Monitor bandwidth in real time
iftop -i eth0

```

## Instant Lock with Dynamic Firewall (iptables) 
to cut malicious traffic on Layer 3/4
```
#!/bin/bash

# Previous flush
iptables -F
iptables -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Existing valid traffic
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Loopback
iptables -A INPUT -i lo -j ACCEPT

# Avoid IP spoofing
iptables -A INPUT -s 10.0.0.0/8 -j DROP
iptables -A INPUT -s 127.0.0.0/8 ! -i lo -j DROP

# Limit SYN by IP
iptables -N DDOS_PROTECT
iptables -A INPUT -p tcp --syn -j DDOS_PROTECT
iptables -A DDOS_PROTECT -m limit --limit 15/s --limit-burst 30 -j RETURN
iptables -A DDOS_PROTECT -j DROP

# ICMP limitato
iptables -A INPUT -p icmp -m limit --limit 1/s -j ACCEPT
iptables -A INPUT -p icmp -j DROP

# HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# SSH with rate limit
iptables -A INPUT -p tcp --dport 22 -m limit --limit 3/min -j ACCEPT

# saving
iptables-save > /etc/iptables/rules.v4

```

## Application Limitations with NGINX to Block HTTP flood and abusive requests on Layer 7
## configuration  (nginx.conf:)
```
http {
  limit_req_zone $binary_remote_addr zone=req_limit_per_ip:10m rate=2r/s;
  limit_conn_zone $binary_remote_addr zone=conn_limit_per_ip:10m;

  server {
    listen 80;
    server_name example.com;

    location / {
      limit_req zone=req_limit_per_ip burst=10 nodelay;
      limit_conn conn_limit_per_ip 5;
    }
  }
}

```
## Apply it with burst+rate limiting and also limit the number of concurrent connections.

## Automation of Mitigation with Fail2Ban for automatic ban malicious IP based logs
## For example NGINX HTTP Flood /etc/fail2ban/jail.local:
```
[nginx-http-flood]
enabled  = true
filter   = nginx-http-flood
logpath  = /var/log/nginx/access.log
maxretry = 100
findtime = 60
bantime  = 3600
action   = iptables[name=HTTP, port=http, protocol=tcp]

```
Filtro /etc/fail2ban/filter. d/nginx-http-flood.conf:
```
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*
ignoreregex =

```
## Cloud Extension (Cloudflare/DNS Proxy) will serve : Outsource protection, filtering, caching
##  Activate:
 "Mode of attack"

Speed limitation

Management of bots

Challenge JS or CAPTCHA

DNS configuration:
Set domain with proxy enabled (orange on Cloudflare)

## script installation of ddos_hardening.sh

```
nano ddos_hardening.sh
```

```
chmod +x ddos_hardening.sh
```
```
sudo ./ddos_hardening.sh
```
