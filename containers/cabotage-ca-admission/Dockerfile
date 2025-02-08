FROM cabotage/base:4

COPY admission.py /opt/cabotage/admission.py
ENTRYPOINT ["gunicorn", "--worker-class", "aiohttp.GunicornWebWorker", "admission:app"]
