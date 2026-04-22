FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Core forensic tools (APT)
RUN apt-get update && apt-get install -y --no-install-recommends \
    sleuthkit \
    ewf-tools \
    yara \
    jq \
    inotify-tools \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Volatility 3
RUN pip3 install --no-cache-dir  volatility3

# Create working directories
RUN mkdir -p /cases /analysis /exports /reports /logs

# Evidence is mounted read-only at /cases
VOLUME ["/cases"]
VOLUME ["/analysis"]

WORKDIR /analysis

CMD ["tail", "-f", "/dev/null"]
