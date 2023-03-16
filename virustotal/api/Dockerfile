FROM python:3.11

RUN mkdir /app
WORKDIR /app

COPY ./logs.yaml /app
COPY ./requirements.txt /app
# Install dependencies
COPY requirements.txt /tmp/
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt && \
  rm -f /tmp/requirements.txt

COPY main.py /app

ENTRYPOINT ["uvicorn", "main:app", "--host", "0.0.0.0", "--log-config", "logs.yaml"]