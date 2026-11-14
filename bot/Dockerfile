FROM python:3.12-slim
RUN pip install --no-cache-dir maxminddb==2.6.2 tzdata
WORKDIR /app
COPY bot.py .
USER nobody
CMD ["python", "-u", "bot.py"]
