FROM python:3.14-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --uid 10001 --create-home signalbridge && mkdir -p var && chown -R signalbridge:signalbridge /app
USER signalbridge
EXPOSE 8000
CMD ["python","scripts/container_web.py"]
