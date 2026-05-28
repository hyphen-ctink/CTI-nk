FROM eclipse-temurin:21-jre

WORKDIR /app

RUN apt-get update && \
    apt-get install -y \
	python3 \
	python3-pip \
	python3-venv \
	python3-full \
	nodejs \
	npm && \
    rm -rf /var/lib/apt/lists/*


# backend
RUN mkdir -p /app/backend
COPY backend/build/libs/ctink-0.0.1-SNAPSHOT.jar /app/backend/app.jar


# frontend
COPY frontend /app/frontend
WORKDIR /app/frontend
RUN npm install
RUN npm run build

WORKDIR /app


# python code
COPY module/cti_collector /app/cti_collector
COPY module/ids_log_forwarder.py /app/ids_log_forwarder.py


# venv
RUN python3 -m venv /venv

COPY requirements.txt /app/requirements.txt

RUN /venv/bin/pip install --no-cache-dir -r /app/requirements.txt


# start 
COPY start.sh /app/start.sh

RUN chmod +x /app/start.sh

CMD ["/app/start.sh"]
