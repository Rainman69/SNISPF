FROM python:3.12-slim

LABEL maintainer="Rainman69"
LABEL description="SNISPF - Cross-platform DPI bypass tool"

WORKDIR /app

COPY pyproject.toml .
COPY sni_spoofing/ ./sni_spoofing/
COPY run.py .
COPY config.json .
COPY README.md .
COPY LICENSE .

RUN pip install --no-cache-dir -e .

EXPOSE 40443

ENTRYPOINT ["snispf"]
CMD ["--config", "config.json"]
