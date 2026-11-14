FROM python:3.12-slim
RUN mkdir -p /var/log/webtrap && chown nobody:nogroup /var/log/webtrap
WORKDIR /app
COPY app.py .
USER nobody
EXPOSE 8080
CMD ["python", "-u", "app.py"]
