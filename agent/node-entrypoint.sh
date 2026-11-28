#!/bin/sh
# NetWatch node entrypoint. Two monitoring baselines run next to the agent, both answering on
# MGMT_NET only (never DATA_NET):
#  - snmpd (snmp/snmpd.conf, planning S2), polled by snmp_exporter;
#  - node_exporter on <mgmt-ip>:9100 (planning S3), scraped by Prometheus.
set -e

snmpd -C -c /etc/netwatch/snmpd.conf -p /tmp/snmpd.pid -Lf /dev/null

MGMT_IP=$(ip -o -4 addr show | awk '$4 ~ /^172\.28\./ { split($4, a, "/"); print a[1]; exit }')
if [ -n "$MGMT_IP" ]; then
  prometheus-node-exporter --web.listen-address="$MGMT_IP:9100" \
    --collector.disable-defaults --collector.cpu --collector.meminfo --collector.netdev \
    --collector.loadavg --collector.uname --collector.time >/dev/null 2>&1 &
fi

exec python -m agent.main
