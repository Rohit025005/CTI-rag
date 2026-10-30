# Web UI in a container; Ollama keeps running on the host (it needs the GPU).
#   docker build -t cti-rag .
#   docker run --rm -v "%cd%/data:/app/data" cti-rag python -m ctirag build-kb      (first time)
#   docker run -p 8000:8000 -v "%cd%/data:/app/data" -v "%cd%/outputs:/app/outputs" cti-rag
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV OLLAMA_HOST=http://host.docker.internal:11434
EXPOSE 8000
CMD ["python", "-m", "ctirag", "serve", "--host", "0.0.0.0", "--port", "8000"]
