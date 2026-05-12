package hyphen.ctink.mq.consumer;

import hyphen.ctink.domain.indicator.UpdateTrustLevelResultService;
import hyphen.ctink.domain.indicator.dto.UpdateTrustLevelJobResultDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UpdateTrustLevelConsumer {

    private final UpdateTrustLevelResultService updateTrustLevelResultService;

    @RabbitListener(queues = "trust.result.queue")
    public void consume(UpdateTrustLevelJobResultDTO result) {
        updateTrustLevelResultService.process(result);
    }

}
