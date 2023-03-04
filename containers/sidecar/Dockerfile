FROM cabotage/base:3

USER root
RUN apt-get update && apt-get install -y musl && rm -rf /var/lib/apt/lists/*
USER nobody
COPY --from=ewdurbin/ghostunnel:latest /usr/bin/ghostunnel /usr/bin/ghostunnel

COPY sidecar.py /opt/cabotage/sidecar.py
ENTRYPOINT ["python", "/opt/cabotage/sidecar.py"]
