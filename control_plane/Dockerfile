FROM python:3.12-slim

COPY requirements/control-plane.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

WORKDIR /app

CMD ["python", "-m", "control_plane.api.grpc_server"]
