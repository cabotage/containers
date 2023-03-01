FROM python:3.11-slim-bullseye

ARG TARGETPLATFORM

ENV PYTHONUNBUFFERED 1

ENV GHOSTUNNEL_FORK=ghostunnel
ENV GHOSTUNNEL_VERSION=v1.5.2

RUN apt-get update && apt-get install wget -y && rm -rf /var/lib/apt/lists/*

RUN case ${TARGETPLATFORM} in \
         "linux/amd64")  ARCH=amd64 ;; \
         "linux/arm64")  ARCH=arm64 ;; \
    esac \
&& wget --quiet https://github.com/${GHOSTUNNEL_FORK}/ghostunnel/releases/download/${GHOSTUNNEL_VERSION}/ghostunnel-${GHOSTUNNEL_VERSION}-linux-${ARCH}-with-pkcs11 \
&& mv ghostunnel-${GHOSTUNNEL_VERSION}-linux-${ARCH}-with-pkcs11 ghostunnel

RUN chmod +x ghostunnel

RUN set -x \
    && python3 -m venv /opt/sidecar

ENV PATH="/opt/sidecar/bin:${PATH}"

RUN pip --no-cache-dir --disable-pip-version-check install --upgrade pip setuptools wheel

COPY requirements.txt /opt/sidecar/requirements.txt

RUN pip --no-cache-dir --disable-pip-version-check install -r /opt/sidecar/requirements.txt

COPY sidecar.py /opt/sidecar/sidecar.py

ENTRYPOINT ["python", "/opt/sidecar/sidecar.py"]
