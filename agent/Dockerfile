FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends iproute2 iputils-ping traceroute && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir grpcio protobuf cryptography

WORKDIR /app

CMD ["sleep", "infinity"]