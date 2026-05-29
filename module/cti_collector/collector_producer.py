import pika
import json
from datetime import datetime

def send_result(results: dict):
    credentials = pika.PlainCredentials("admin", "StrongPassword123!")

    connection = pika.BlockingConnection(
        pika.ConnectionParameters(
            host="158.247.213.206",
            port=5672,
            credentials=credentials
        )
    )
    channel = connection.channel()
    channel.queue_declare(queue='collector.result.queue', durable=True)

    for item in results:
        try:
            if isinstance(item.get("collected_at"), datetime):
                item["collected_at"] = item["collected_at"].isoformat()

            channel.basic_publish(
                exchange='',
                routing_key='collector.result.queue',
                body=json.dumps(item),
                properties=pika.BasicProperties(
                    delivery_mode=2
                )
            )

        except Exception as e:
            print("error:", e)

    connection.close()