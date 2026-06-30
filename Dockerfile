FROM python:3.13.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --timeout 120 -r requirements.txt

RUN addgroup --system app && adduser --system --ingroup app app

COPY src ./src
COPY config ./config

EXPOSE 8000

USER app

CMD ["uvicorn", "main:app", "--app-dir", "src", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
