package hyphen.ctink.domain.collector;

import hyphen.ctink.domain.collector.dto.CollectorJobDTO;
import hyphen.ctink.domain.platform.CollectionPlatform;
import hyphen.ctink.domain.platform.CollectionPlatformRepository;
import hyphen.ctink.mq.producer.CollectorProducer;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class CollectorService {

    private final CollectorProducer producer;
    private final CollectionPlatformRepository collectionPlatformRepository;

    public void collect(Long platformId) {

        CollectionPlatform platform = collectionPlatformRepository.findById(platformId)
                .orElseThrow();

        String jobId = UUID.randomUUID().toString();

        CollectorJobDTO message = new CollectorJobDTO(
                jobId,
                platformId,
                platform.getLastCommitSha(),
                platform.getLastCollectedAt()
        );

        producer.send(message);
    }
}
