package hyphen.ctink.domain.collector;

import hyphen.ctink.domain.collector.dto.CollectorResultDTO;
import hyphen.ctink.domain.cti.CtiDataRepository;
import hyphen.ctink.domain.cti.entity.CtiData;
import hyphen.ctink.domain.cti.enums.ProcessStatus;
import hyphen.ctink.domain.platform.CollectionPlatform;
import hyphen.ctink.domain.platform.CollectionPlatformRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class CollectorResultService {
    private final CtiDataRepository ctiDataRepository;
    private final CollectionPlatformRepository collectionPlatformRepository;

    @Transactional
    public void process(CollectorResultDTO result) {
        if (!"success".equals(result.status())) {
            return;
        }

        var item = result.item();

        CollectionPlatform platform = collectionPlatformRepository.findById(result.platformId())
                .orElseThrow(() -> new RuntimeException("Platform not found"));


        CtiData entity = CtiData.builder()
                .collectionPlatform(platform)
                .sourceUrl(item.sourceUrl())
                .summaryTitle(null)
                .summaryContent(null)
                .rawData(item.rawContent())
                .attackType(null)
                .processStatus(ProcessStatus.COLLECTED)
                .collectedAt(result.collectedAt())
                .updatedAt(LocalDateTime.now())
                .build();

        ctiDataRepository.save(entity);

        platform.updateLastCollectedAt(LocalDateTime.now());
    }
}
