package hyphen.ctink.mq.consumer;

import hyphen.ctink.domain.collector.CollectorResultService;
import hyphen.ctink.domain.collector.dto.CollectorResultDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CollectorConsumer {

    private final CollectorResultService collectorResultService;

    @RabbitListener(queues = "collector.result.queue")
    public void consume(CollectorResultDTO result) {
        collectorResultService.process(result);
    }
}
