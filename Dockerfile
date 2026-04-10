FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/

EXPOSE 9020

ENV A2A_PORT=9020

CMD ["python", "-m", "src.server", "--host", "0.0.0.0"]
