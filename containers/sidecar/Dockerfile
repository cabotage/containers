FROM cabotage/base:4

USER root
RUN apt-get update && apt-get install -y musl && rm -rf /var/lib/apt/lists/*
USER nobody
COPY --from=ghostunnel/ghostunnel:v1.8.4 /usr/bin/ghostunnel /usr/bin/ghostunnel

COPY sidecar.py /opt/cabotage/sidecar.py
ENTRYPOINT ["python", "/opt/cabotage/sidecar.py"]
