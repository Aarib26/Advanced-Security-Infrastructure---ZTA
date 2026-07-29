FROM python:3.12-alpine
RUN pip install --no-cache-dir flask
WORKDIR /app
COPY app.py .
EXPOSE 8080
CMD ["python", "app.py"]
