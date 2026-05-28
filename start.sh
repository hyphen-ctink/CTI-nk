echo "Starting backend spring boot::"
java -jar /app/backend/app.jar &

echo "Starting collector-consumer::"
python /app/cti_collector/collector_consumer.py &

echo "Starting trust-consumer::"
python /app/cti_collector/trust_consumer.py &

echo "Starting ids-log-producer::"
python /app/ids_log_forwarder.py &

echo "Starting frontend node js::"
cd /app/frontend
npm start &

wait
