package hyphen.ctink.domain.rule;

import hyphen.ctink.domain.cti.entity.CtiData;
import hyphen.ctink.domain.cti.enums.AttackType;
import hyphen.ctink.domain.indicator.IocDTO;
import hyphen.ctink.domain.indicator.IocRepository;
import hyphen.ctink.domain.indicator.enums.TrustLevel;
import hyphen.ctink.domain.relation.DetectionRuleIocRepository;
import hyphen.ctink.domain.relation.IocCtiRepository;
import hyphen.ctink.domain.rule.dto.DetectionRuleDetailDTO;
import hyphen.ctink.domain.rule.dto.DetectionRuleDetailResponseDTO;
import hyphen.ctink.domain.rule.dto.SnortDTO;
import hyphen.ctink.domain.rule.dto.YaraDTO;
import hyphen.ctink.domain.rule.entity.DetectionRule;
import hyphen.ctink.domain.rule.enums.RuleType;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class DetectionRuleDetailService {
    private final DetectionRuleRepository detectionRuleRepository;
    private final IocCtiRepository iocCtiRepository;
    private final DetectionRuleIocRepository detectionRuleIocRepository;
    private final IocRepository iocRepository;

    public DetectionRuleDetailResponseDTO getRuleDetail(Integer ruleId) {
        DetectionRule detectionRule = detectionRuleRepository.findById(Long.valueOf(ruleId))
                .orElseThrow(() -> new RuntimeException("Rule not found"));

        CtiData cti = detectionRule.getCti();

        Long ctiId = cti.getId();
        String sourceUrl = cti.getSourceUrl();
        AttackType attackType = cti.getAttackType();

        List<Long> iocIdList = iocCtiRepository.findIocIdsByCtiId(ctiId);
        List<IocDTO> iocList = iocRepository.findByIdIn(iocIdList).stream()
                .map(ioc -> new IocDTO(
                        ioc.getIocType(),
                        ioc.getIocValue()
                ))
                .toList();

        TrustLevel trustLevel = detectionRule.getTrustLevel();

        DetectionRuleDetailDTO ruleDetail = new DetectionRuleDetailDTO(
                detectionRule.getId(),
                detectionRule.getRuleName(),
                detectionRule.getRuleType(),
                detectionRule.getRuleStatus(),
                detectionRule.getOsType(),
                detectionRule.getRuleContent(),
                detectionRule.getGrammarResult(),
                detectionRule.getFnResult(),
                detectionRule.getFpResult(),
                detectionRule.getAgentJudgement(),
                detectionRule.getRegenCount(),
                detectionRule.getCreatedAt()
        );

        List<Long> ruleIdList = detectionRuleIocRepository.findRuleIdsByIocIds(iocIdList);
        List<DetectionRule> rules = detectionRuleRepository.findByIdIn(ruleIdList);
        List<SnortDTO> snortList = rules.stream()
                .filter(r -> r.getRuleType() == RuleType.SNORT)
                .map(r -> new SnortDTO(r.getId(), r.getRuleName(), r.getRuleContent()))
                .toList();
        List<YaraDTO> yaraList = rules.stream()
                .filter(r -> r.getRuleType() == RuleType.YARA)
                .map(r -> new YaraDTO(r.getId(), r.getRuleName(), r.getOsType(), r.getRuleContent()))
                .toList();

        return new DetectionRuleDetailResponseDTO(
                ctiId,
                sourceUrl,
                attackType,
                iocList,
                trustLevel,
                ruleDetail,
                snortList,
                yaraList
        );
    }
}

