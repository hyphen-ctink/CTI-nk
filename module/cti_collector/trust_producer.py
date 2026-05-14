import pika
import json
from datetime import datetime

def send_result(message: dict):
    connection = pika.BlockingConnection(pika.ConnectionParameters(host="localhost"))
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