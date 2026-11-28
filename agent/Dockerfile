FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends iproute2 iputils-ping traceroute iperf3 tcpdump snmp snmpd prometheus-node-exporter && \
    rm -rf /var/lib/apt/lists/*

COPY requirements/agent.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

WORKDIR /app

CMD ["python", "-m", "agent.main"]
