FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
COPY model/ model/
COPY inference.py .
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 5000
CMD ["python", "inference.py"]