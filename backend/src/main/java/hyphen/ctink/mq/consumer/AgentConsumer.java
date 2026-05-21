package hyphen.ctink.mq.consumer;

import hyphen.ctink.domain.agent.AgentResultService;
import hyphen.ctink.domain.agent.dto.AgentJobResultDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AgentConsumer {

    private final AgentResultService agentResultService;

    @RabbitListener(queues = "analysis.result.queue")
    public void consume(AgentJobResultDTO result) {
        agentResultService.process(result);
    }

}
