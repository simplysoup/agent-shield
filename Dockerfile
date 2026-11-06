FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir '.[api]'
USER 65532:65532
EXPOSE 8000
CMD ["uvicorn","agentshield.api.main:create_app","--factory","--host","127.0.0.1","--port","8000"]
