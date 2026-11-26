FROM python:3.12-slim

RUN pip install --no-cache-dir nats-py psycopg[binary]

WORKDIR /app

CMD ["python", "-m", "worker.main"]