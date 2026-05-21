package hyphen.ctink.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.amqp.core.QueueBuilder;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.support.converter.MessageConverter;

@Configuration
public class RabbitMQConfig {

    public static final String COLLECT_QUEUE = "collector.queue";
    public static final String COLLECT_RESULT_QUEUE = "collector.result.queue";
    public static final String TRUST_QUEUE = "trust.queue";
    public static final String TRUST_RESULT_QUEUE = "trust.result.queue";
    public static final String AGENT_QUEUE = "analysis.request.queue";
    public static final String AGENT_RESULT_QUEUE = "analysis.result.queue";

    @Bean
    public Queue collectQueue() {
        return QueueBuilder
                .durable(COLLECT_QUEUE)
                .build();
    }

    @Bean
    public Queue collectResultQueue() {
        return QueueBuilder
                .durable(COLLECT_RESULT_QUEUE)
                .build();
    }

    @Bean
    public Queue trustQueue() {
        return QueueBuilder
                .durable(TRUST_QUEUE)
                .build();
    }

    @Bean
    public Queue trustResultQueue() {
        return QueueBuilder
                .durable(TRUST_RESULT_QUEUE)
                .build();
    }

    @Bean
    public Queue agentQueue() {
        return QueueBuilder
                .durable(AGENT_QUEUE)
                .build();
    }

    @Bean
    public Queue agentResultQueue() {
        return QueueBuilder
                .durable(AGENT_RESULT_QUEUE)
                .build();
    }

    @Bean
    public MessageConverter messageConverter(ObjectMapper objectMapper) {
        return new Jackson2JsonMessageConverter(objectMapper);
    }

    @Bean
    public RabbitTemplate rabbitTemplate(
            ConnectionFactory connectionFactory,
            MessageConverter messageConverter
    ) {
        RabbitTemplate template = new RabbitTemplate(connectionFactory);
        template.setMessageConverter(messageConverter);
        return template;
    }
}
