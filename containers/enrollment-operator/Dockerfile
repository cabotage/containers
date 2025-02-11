FROM cabotage/base:4

USER root
COPY requirements.txt /opt/cabotage/requirements.txt

RUN pip --no-cache-dir --disable-pip-version-check install -r /opt/cabotage/requirements.txt
USER nobody

COPY operator.py /opt/cabotage/operator.py
ENTRYPOINT ["kopf", "run", "/opt/cabotage/operator.py", "--all-namespaces"]
