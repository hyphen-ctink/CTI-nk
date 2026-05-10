package hyphen.ctink.domain.rule;

import hyphen.ctink.domain.rule.dto.DetectionRuleDTO;
import hyphen.ctink.domain.rule.dto.DetectionRuleRequestDTO;
import hyphen.ctink.domain.rule.dto.DetectionRuleResponseDTO;
import hyphen.ctink.domain.rule.dto.RuleSearchConditionDTO;
import hyphen.ctink.domain.rule.entity.DetectionRule;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class DetectionRuleService {
    private final RuleQueryRepository ruleQueryRepository;

    public DetectionRuleResponseDTO getRule(DetectionRuleRequestDTO req) {
        int page = (req.page() == null ? 1 : req.page());

        Pageable pageable = PageRequest.of(
                page - 1,
                15,
                Sort.by("createdAt").descending()
        );

        RuleSearchConditionDTO condition = new RuleSearchConditionDTO(
                req.search(),
                req.ruleType(),
                req.attackType(),
                req.trustLevel(),
                req.status(),
                req.dateFrom() != null ? LocalDateTime.parse(req.dateFrom()): null,
                req.dateTo() != null ? LocalDateTime.parse(req.dateTo()) : null
        );

        Page<DetectionRule> queryResult = ruleQueryRepository.search(condition, pageable);
        Page<DetectionRuleDTO> result = queryResult.map(detectionRule ->
                new DetectionRuleDTO(
                        detectionRule.getId(),
                        detectionRule.getRuleName(),
                        detectionRule.getRuleType(),
                        detectionRule.getAttackType(),
                        detectionRule.getTrustLevel(),
                        detectionRule.getRuleStatus(),
                        detectionRule.getCreatedAt()
                )
        );

        return new DetectionRuleResponseDTO(
                result.getTotalElements(),
                (long) result.getTotalPages(),
                (long) (result.getNumber() + 1),
                result.getContent()
        );
    }
}
