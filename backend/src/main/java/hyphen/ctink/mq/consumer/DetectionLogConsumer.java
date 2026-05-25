package hyphen.ctink.mq.consumer;

import hyphen.ctink.domain.log.ids.IdsDetectionResultService;
import hyphen.ctink.domain.log.ids.dto.IdsDetectionResultDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DetectionLogConsumer {

    private final IdsDetectionResultService idsDetectionResultService;

    @RabbitListener(queues = "log.result.queue")
    public void consume(IdsDetectionResultDTO result) {
        idsDetectionResultService.process(result);
    }
}
