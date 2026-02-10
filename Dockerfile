FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends libsodium-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir .

EXPOSE 5060/udp 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
