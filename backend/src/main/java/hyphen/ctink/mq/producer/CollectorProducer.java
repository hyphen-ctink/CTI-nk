package hyphen.ctink.mq.producer;

import hyphen.ctink.domain.collector.dto.CollectorJobDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CollectorProducer {

    private final RabbitTemplate rabbitTemplate;

    public void send(CollectorJobDTO message) {
        rabbitTemplate.convertAndSend(
                "collector.queue",
                message
        );
    }
}
