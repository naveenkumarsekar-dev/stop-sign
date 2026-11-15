FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -m app && mkdir -p /app/data && chown -R app /app
USER app
ENV STOPSIGN_DB=/app/data/stopsign.db
EXPOSE 8000 8501
CMD ["uvicorn", "honeypot.app:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
