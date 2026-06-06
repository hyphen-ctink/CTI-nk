#AI 서버 진입점.

import logging

from app.config import settings
from app.graph.workflow import get_workflow
from app.mq.consumer import start_consumer


def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


def main() -> None:
    _setup_logging()
    
    logger = logging.getLogger(__name__)
    logger.info("=" * 70)
    logger.info("CTI-nk AI 서버 시작")
    logger.info("=" * 70)
    logger.info(f"RabbitMQ URL: {settings.rabbitmq_url}")
    logger.info(f"요청 큐: {settings.mq_request_queue}")
    logger.info(f"응답 큐: {settings.mq_response_queue}")
    
    logger.info("LangGraph 워크플로우 빌드 중...")
    workflow = get_workflow()
    logger.info(
        f"워크플로우 빌드 완료. 노드 수: "
        f"{len(list(workflow.get_graph().nodes.keys()))}"
    )
    
    logger.info("MQ Consumer 시작...")
    start_consumer()


if __name__ == "__main__":
    main()