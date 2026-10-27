# Requires a preloaded local image; this recipe does not install/download packages.
FROM python:3.11-slim
WORKDIR /app
COPY server.py /app/server.py
USER 65534:65534
CMD ["python", "-I", "-B", "/app/server.py"]
