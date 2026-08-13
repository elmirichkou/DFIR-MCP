FROM python:3.12-slim

# System deps Volatility 3 sometimes needs (yara, unicode libs)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY run_plugin.py .

# Images and symbol tables are mounted at runtime, not baked into the image
RUN mkdir -p /images /symbols

EXPOSE 8000

CMD ["uvicorn", "run_plugin:app", "--host", "0.0.0.0", "--port", "8000"]
