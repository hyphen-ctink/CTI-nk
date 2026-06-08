#!/bin/sh

echo "Starting collector-consumer::"
python /app/cti_collector/collector_consumer.py &

echo "Starting trust-consumer::"
python /app/cti_collector/trust_consumer.py &

echo "Starting ids-log-producer::"
python /app/ids_log_forwarder.py &

wait
