FROM python:3.12-slim
RUN pip install --no-cache-dir cryptography
COPY app.py /app.py
EXPOSE 8080
CMD ["python", "/app.py"]
