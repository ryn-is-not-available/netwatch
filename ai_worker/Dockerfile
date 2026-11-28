FROM python:3.12-slim

COPY requirements/ai-worker.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt &&     useradd --system --uid 10001 --no-create-home netwatch-ai

WORKDIR /app
USER 10001

CMD ["uvicorn", "ai_worker.main:app", "--host", "0.0.0.0", "--port", "8100"]
