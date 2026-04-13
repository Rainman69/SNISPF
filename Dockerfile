FROM python:3.12-slim

LABEL maintainer="patterniha"
LABEL description="SNI-Spoofing CLI - Cross-platform DPI bypass tool"

WORKDIR /app

COPY pyproject.toml .
COPY sni_spoofing/ ./sni_spoofing/
COPY run.py .
COPY config.json .
COPY README.md .
COPY LICENSE .

RUN pip install --no-cache-dir -e .

EXPOSE 40443

ENTRYPOINT ["sni-spoofing"]
CMD ["--config", "config.json"]
