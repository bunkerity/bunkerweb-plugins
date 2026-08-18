FROM python:3.12-slim
# Standard library only: the mock speaks TLS 1.3 through ssl and serves JSON by hand,
# exactly like SysWarden's own Go server does without a framework.
COPY app.py /app.py
EXPOSE 62026
CMD ["python", "/app.py"]
