FROM python:3.12-slim

RUN pip install --no-cache-dir grpcio protobuf cryptography nats-py psycopg[binary] fastapi uvicorn[standard] PyJWT

WORKDIR /app

CMD ["python", "-m", "control_plane.api.grpc_server"]