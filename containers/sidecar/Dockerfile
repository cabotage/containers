FROM cabotage/base:3

COPY --from=ghostunnel/ghostunnel:v1.7.1 /usr/bin/ghostunnel /usr/bin/ghostunnel

COPY sidecar.py /opt/cabotage/sidecar.py
ENTRYPOINT ["python", "/opt/cabotage/sidecar.py"]
