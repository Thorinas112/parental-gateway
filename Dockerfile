# ---------------------------------------------------------------------------
# Parental Gateway
# Containerised parental-control / network-management gateway.
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TZ=UTC

# System tooling used by the gateway / scanner / firewall backends.
#   iproute2      -> ip (interface + neighbour inspection)
#   iptables      -> MAC based firewall rules + NAT
#   iputils-arping, arp-scan -> layer-2 device discovery helpers
#   libpcap0.8    -> scapy packet capture / ARP
#   procps        -> sysctl
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        iptables \
        iproute2 \
        iputils-arping \
        arp-scan \
        libpcap0.8 \
        procps \
        ca-certificates \
        tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime \
    && echo $TZ > /etc/timezone

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app /app/app
COPY docs /app/docs
COPY README.md /app/README.md
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
    && mkdir -p /app/data

# Web UI
EXPOSE 8080

# Persistent SQLite database + generated secret key
VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
    CMD python -c "import urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=4).status==200 else 1)"

ENTRYPOINT ["/entrypoint.sh"]
