FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir -e . 2>/dev/null || pip install --no-cache-dir fastapi[standard] uvicorn[standard] httpx dnspython beautifulsoup4 jinja2 python-multipart pydantic email-validator

COPY . .

RUN mkdir -p /data

ENV DB_PATH=/data/securescan.db

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
