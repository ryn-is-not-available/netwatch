FROM python:3.12-slim

RUN apt-get update && apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends iproute2 iputils-ping traceroute && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

CMD ["sleep", "infinity"]