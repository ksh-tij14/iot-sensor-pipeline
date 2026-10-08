# One image definition for all five Python services; SERVICE picks which one runs.
FROM python:3.13-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ shared/
COPY gateway/ gateway/
COPY fork/ fork/
COPY edge/ edge/
COPY cloud/ cloud/
COPY validation/ validation/
COPY dashboard/ dashboard/
COPY tests/ tests/

ARG SERVICE
ENV SERVICE=${SERVICE}
CMD python -m ${SERVICE}
