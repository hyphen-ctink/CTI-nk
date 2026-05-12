package hyphen.ctink.mq.producer;

import hyphen.ctink.domain.indicator.dto.UpdateTrustLevelJobDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UpdateTrustLevelProducer {

    private final RabbitTemplate rabbitTemplate;

    public void send(UpdateTrustLevelJobDTO message) {
        rabbitTemplate.convertAndSend(
                "trust.queue",
                message
        );
    }
}
