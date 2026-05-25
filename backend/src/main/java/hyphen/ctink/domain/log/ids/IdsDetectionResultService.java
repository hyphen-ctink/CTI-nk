package hyphen.ctink.domain.log.ids;

import hyphen.ctink.domain.log.ids.dto.IdsDetectionResultDTO;
import hyphen.ctink.domain.log.ids.entity.IdsDetectionLog;
import hyphen.ctink.domain.rule.DetectionRuleRepository;
import hyphen.ctink.domain.rule.entity.DetectionRule;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class IdsDetectionResultService {

    private final IdsDetectionLogRepository idsDetectionLogRepository;
    private final DetectionRuleRepository detectionRuleRepository;

    @Transactional
    public void process(IdsDetectionResultDTO result) {

        DetectionRule rule = detectionRuleRepository.findByRuleContent(result.ruleContent())
                .orElseThrow();
        
        IdsDetectionLog log = IdsDetectionLog.builder()
                .attackType(rule.getAttackType())
                .detail(result.detail())
                .result(result.result())
                .detectedAt(result.detectedAt())
                .build();

        idsDetectionLogRepository.save(log);
    }
}
