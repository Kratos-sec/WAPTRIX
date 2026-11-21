# WAPTrix API + external tool belt. Built locally so every machine gets a native-arch image.
FROM kalilinux/kali-last-release:latest

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH

# Tools: nmap whatweb nikto wapiti sqlmap testssl.sh nuclei (Kali packages), retire (npm), sslyze (pip).
# libpango* are WeasyPrint's runtime libraries for PDF export.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates python3 python3-venv \
      nmap whatweb nikto wapiti sqlmap testssl.sh nuclei \
      nodejs npm \
      libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fonts-dejavu-core \
 && npm install -g --no-fund --no-audit retire@6.1.1 \
 && npm cache clean --force \
 && apt-get purge -y npm && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml ./
COPY app ./app
COPY sample_data ./sample_data
RUN python3 -m venv /opt/venv \
 && pip install --no-cache-dir ".[pdf]" "sslyze==6.3.1"

# Unprivileged runtime user. Nmap uses TCP connect scans (-sT), which need no raw-socket rights.
RUN useradd --create-home --uid 10001 waptrix && mkdir -p /data && chown waptrix /data
USER waptrix
ENV WAPTRIX_DB=/data/waptrix.db

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
