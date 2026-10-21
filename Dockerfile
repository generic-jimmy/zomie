FROM python:3.12-slim

WORKDIR /app

# Install dependencies first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py scanner.py ./
COPY templates/ templates/
COPY static/ static/

# Run as an unprivileged user
RUN useradd --create-home scopeuser
USER scopeuser

EXPOSE 5000

CMD ["python", "app.py"]
