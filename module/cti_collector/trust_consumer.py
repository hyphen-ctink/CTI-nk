import pika
import json
from trust.misp_search import is_exist_misp
from trust.vt_search import is_exist_vi
from trust_producer import send_result

def callback(ch, method, properties, body):
    data = json.loads(body)

    ioc = data.get("ioc")
    platform = data.get("platform")
    
    try:
        if platform == "misp":
            result = is_exist_misp(ioc)
        else:
            result = is_exist_vi(ioc)

        message = {
            "ioc": ioc,
            "status": "success",
            "platform": platform,
            "result": result
        }

        print(ioc, platform, result)
        send_result(message)
        ch.basic_ack(delivery_tag=method.delivery_tag)

    except Exception as e:
        message = {
            "ioc": ioc,
            "status": "failed",
            "platform": platform,
            "result": None
        }

        send_result(message)
        ch.basic_ack(delivery_tag=method.delivery_tag)

credentials = pika.PlainCredentials("admin", "StrongPassword123!")

connection = pika.BlockingConnection(
    pika.ConnectionParameters(
        host="158.247.213.206",
        port=5672,
        credentials=credentials
    )
)
channel = connection.channel()

channel.queue_declare(queue='trust.queue', durable=True)
channel.basic_qos(prefetch_count=1)

channel.basic_consume(
    queue='trust.queue',
    on_message_callback=callback
)

channel.start_consuming()