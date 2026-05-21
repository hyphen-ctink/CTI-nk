package hyphen.ctink.mq.producer;

import hyphen.ctink.domain.agent.dto.AgentJobDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AgentProducer {

    private final RabbitTemplate rabbitTemplate;

    public void send(AgentJobDTO message) {
        rabbitTemplate.convertAndSend(
                "analysis.request.queue",
                message
        );
    }
}
