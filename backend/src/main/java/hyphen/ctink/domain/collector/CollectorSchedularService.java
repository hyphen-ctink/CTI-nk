package hyphen.ctink.domain.collector;

import hyphen.ctink.domain.collector.dto.CollectorJobDTO;
import hyphen.ctink.domain.cti.CtiDataRepository;
import hyphen.ctink.domain.platform.CollectionPlatform;
import hyphen.ctink.domain.platform.CollectionPlatformRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class CollectorSchedularService {

    private final CollectionPlatformRepository platformRepository;
    private final CtiDataRepository ctiDataRepository;
    private final CollectorService collectorService;

    @Transactional
    public void runCollection() {
        LocalDateTime now = LocalDateTime.now();

        List<CollectionPlatform> platforms = platformRepository.findAll();

        for (CollectionPlatform platform: platforms) {
            if (platform.getLastCollectedAt() != null && !platform.nextCollectTime(now)) {
                continue;
            }

            collectorService.collect(platform.getId());
        }
    }

    @Transactional
    public void collectionCycleControl() {
        List<CollectionPlatform> platforms = platformRepository.findAll();

        for (CollectionPlatform platform : platforms) {
            long count = ctiDataRepository.countByCollectionPlatformAndCollectedAtBetween(
                    platform,
                    platform.getCycleResetAt(),
                    platform.getLastCollectedAt()
            );

            if (count >= 100) {
                platform.setCurrentIntervalTime(3);
            } else {
                platform.setCurrentIntervalTime(7);
            }
        }
    }
}
