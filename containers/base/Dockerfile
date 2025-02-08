FROM python:3.13-slim-bookworm

ENV PYTHONUNBUFFERED 1

RUN set -x \
    && python3 -m venv /opt/cabotage

ENV PATH="/opt/cabotage/bin:${PATH}"

RUN pip --no-cache-dir --disable-pip-version-check install --upgrade pip setuptools wheel

COPY requirements.txt /opt/cabotage/requirements.txt

RUN pip --no-cache-dir --disable-pip-version-check install -r /opt/cabotage/requirements.txt

WORKDIR /opt/cabotage

USER nobody
