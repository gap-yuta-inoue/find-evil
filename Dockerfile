FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Core forensic tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    sleuthkit \
    bulk-extractor \
    ewf-tools \
    yara \
    jq \
    inotify-tools \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Volatility 3
RUN python3 -m pip install --no-cache-dir volatility3

# Plaso (log2timeline)
RUN python3 -m pip install --no-cache-dir plaso

# Create working directories
RUN mkdir -p /cases /analysis /exports /reports /logs

# Evidence is mounted read-only at /cases
VOLUME ["/cases"]

# Analysis output
VOLUME ["/analysis"]

WORKDIR /analysis

# Health check
HEALTHCHECK --interval=30s --timeout=5s \
    CMD which vol3 && which mmls && which log2timeline.py || exit 1

# Keep container running for exec
CMD ["tail", "-f", "/dev/null"]
