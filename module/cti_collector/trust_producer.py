import pika
import json
from datetime import datetime

def send_result(message: dict):
    credentials = pika.PlainCredentials("admin", "StrongPassword123!")

    connection = pika.BlockingConnection(
        pika.ConnectionParameters(
            host="141.164.37.213",
            port=5672,
            credentials=credentials
        )
    )
    channel = connection.channel()
    channel.queue_declare(queue='trust.result.queue', durable=True)

    try:
        channel.basic_publish(
            exchange='',
            routing_key='trust.result.queue',
            body=json.dumps(message),
            properties=pika.BasicProperties(
                delivery_mode=2
            )
        )

    except Exception as e:
        print("error:", e)

    connection.close()