FROM python:3.12-slim

COPY requirements/worker.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

WORKDIR /app

CMD ["python", "-m", "worker.main"]
