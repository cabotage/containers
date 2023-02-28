FROM python:3.11-slim-bullseye

ENV PYTHONUNBUFFERED 1

RUN set -x \
    && python3 -m venv /opt/admission

ENV PATH="/opt/admission/bin:${PATH}"

RUN pip --no-cache-dir --disable-pip-version-check install --upgrade pip setuptools wheel

COPY requirements.txt /opt/admission/requirements.txt

RUN pip --no-cache-dir --disable-pip-version-check install -r /opt/admission/requirements.txt

COPY admission.py /opt/admission/admission.py

USER nobody
WORKDIR /opt/admission
ENTRYPOINT ["gunicorn", "--worker-class", "aiohttp.GunicornWebWorker", "admission:app"]
