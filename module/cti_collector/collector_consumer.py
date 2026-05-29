import pika
import json
from datetime import datetime, timedelta
from collector.collector import collector_start
from collector_producer import send_result

from flask import Flask, request, jsonify
import requests


def callback(ch, method, properties, body):
    data = json.loads(body)

    job_id = data.get("job_id")
    platform_id = data.get("platform_id")
    last_commit_sha = data.get("last_commit_sha")
    last_collected_at = data.get("last_collected_at")

    payload = {
        "platform_id": platform_id,
        "last_commit_sha": last_commit_sha,
        "last_collected_at": last_collected_at
    } 
    
    try:
        result = collector_start(payload)
        send_result(result)
        ch.basic_ack(delivery_tag=method.delivery_tag)

    except Exception as e:
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)

credentials = pika.PlainCredentials("admin", "StrongPassword123!")

connection = pika.BlockingConnection(
    pika.ConnectionParameters(
        host="158.247.213.206",
        port=5672,
        credentials=credentials
    )
)
channel = connection.channel()

channel.queue_declare(queue='collector.queue', durable=True)
channel.basic_qos(prefetch_count=1)

channel.basic_consume(
    queue='collector.queue',
    on_message_callback=callback
)

channel.start_consuming()