package hyphen.ctink.mq.producer;

import hyphen.ctink.domain.indicator.dto.SearchIocJobDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class SearchIocProducer {

    private final RabbitTemplate rabbitTemplate;

    public void send(SearchIocJobDTO message) {
        rabbitTemplate.convertAndSend(
                "trust.queue",
                message
        );
    }
}
