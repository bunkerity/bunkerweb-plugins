FROM python:3.11-alpine

RUN mkdir /app
WORKDIR /app

COPY ./logs.yaml /app
COPY ./requirements.txt /app
# Install dependencies
COPY requirements.txt /tmp/
RUN apk add --no-cache --virtual .build-deps rust cargo && \
  pip3 install --no-cache-dir -r /tmp/requirements.txt && \
  rm -f /tmp/requirements.txt && \
  apk del .build-deps

COPY *.py /app

ENTRYPOINT ["uvicorn", "main:app", "--host", "0.0.0.0", "--log-config", "logs.yaml"]
