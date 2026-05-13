package hyphen.ctink.mq.consumer;

import hyphen.ctink.domain.indicator.SearchIocResultService;
import hyphen.ctink.domain.indicator.dto.SearchIocJobResultDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class SearchIocConsumer {

    private final SearchIocResultService updateTrustLevelResultService;

    @RabbitListener(queues = "trust.result.queue")
    public void consume(SearchIocJobResultDTO result) {
        updateTrustLevelResultService.process(result);
    }

}
