package hyphen.ctink.domain.agent;


import hyphen.ctink.domain.agent.dto.AgentJobResultDTO;
import hyphen.ctink.domain.cti.AttackDetailRepository;
import hyphen.ctink.domain.cti.CtiDataRepository;
import hyphen.ctink.domain.cti.OtherThreatRepository;
import hyphen.ctink.domain.log.notification.OtherThreatLogService;
import hyphen.ctink.domain.cti.entity.AttackDetail;
import hyphen.ctink.domain.cti.entity.CtiData;
import hyphen.ctink.domain.cti.entity.OtherThreat;
import hyphen.ctink.domain.cti.enums.AttackType;
import hyphen.ctink.domain.cti.enums.CtiPlatform;
import hyphen.ctink.domain.cti.enums.ProcessStatus;
import hyphen.ctink.domain.indicator.Ioc;
import hyphen.ctink.domain.indicator.IocRepository;
import hyphen.ctink.domain.indicator.UpdateTrustLevelService;
import hyphen.ctink.domain.indicator.enums.IoCStatus;
import hyphen.ctink.domain.indicator.enums.TrustLevel;
import hyphen.ctink.domain.log.notification.PendingRuleLogService;
import hyphen.ctink.domain.rule.DetectionRuleRepository;
import hyphen.ctink.domain.rule.entity.DetectionRule;
import hyphen.ctink.domain.rule.enums.RuleStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class AgentResultService {

    private final CtiDataRepository ctiDataRepository;
    private final DetectionRuleRepository detectionRuleRepository;
    private final IocRepository iocRepository;
    private final OtherThreatRepository otherThreatRepository;
    private final AttackDetailRepository attackDetailRepository;

    private final UpdateTrustLevelService updateTrustLevelService;
    private final OtherThreatLogService otherThreatLogService;
    private final PendingRuleLogService pendingRuleLogService;

    @Transactional
    public void process(AgentJobResultDTO result) {
        CtiData ctiData = ctiDataRepository.findById(result.ctiDataId())
                .orElseThrow(() -> new RuntimeException("Cti data not found"));

        if (!"success".equals(result.status())) {
            ctiData.updateProcessStatus(ProcessStatus.FAILED);
            return;
        }

        ctiData.updateAnalysisResult(result.summary(), result.attackType());

        // 기타 유형인 경우
        if (result.attackType() == AttackType.OTHER) {
            OtherThreat threat = OtherThreat.builder()
                    .ctiData(ctiData)
                    .suspectedType(String.valueOf(result.attackType()))
                    .analyzedAt(LocalDateTime.now())
                    .build();

            otherThreatRepository.save(threat);
            otherThreatLogService.otherThreatLog();

            return;
        }

        // 기타 유형이 아닌 경우
        // 이미 존재하는 ioc인 경우
        if (iocRepository.existsByIocValue(result.detectionRule().iocValue())) {
            Ioc ioc = iocRepository.findByIocValue(result.detectionRule().iocValue())
                    .orElseThrow();

            CtiPlatform platform = ctiData.getCollectionPlatform().getName();

            if (!ioc.getPlatformName().contains(platform)) {
                ioc.getPlatformName().add(platform);
                updateTrustLevelService.updateTrustLevel(ioc.getId());
            }

            return;
        }

        // 새로운 ioc인 경우
        Ioc ioc = Ioc.builder()
                .platformName(
                        Set.of(
                                ctiData.getCollectionPlatform().getName()
                        )
                )
                .iocType(result.detectionRule().iocType())
                .iocValue(result.detectionRule().iocValue())
                .virustotalConfirmed(false)
                .mispConfirmed(false)
                .trustLevel(TrustLevel.LOW)
                .createdAt(LocalDateTime.now())
                .ioCStatus(IoCStatus.ACTIVE)
                .build();

        iocRepository.save(ioc);

        long ruleNum = detectionRuleRepository.countByAttackType(result.attackType());
        String ruleName = result.attackType().name() + "_" + (ruleNum + 1);

        DetectionRule rule = DetectionRule.builder()
                .cti(ctiData)
                .ruleName(ruleName)
                .ruleType(result.detectionRule().ruleType())
                .ruleContent(result.detectionRule().ruleContent())
                .attackType(result.attackType())
                .trustLevel(ioc.getTrustLevel())
                .version(1)
                .regenCount(result.regenCount())
                .ruleStatus(RuleStatus.PENDING)
                .grammarResult(result.feedback().grammarFeedback())
                .fnResult(result.feedback().fnFeedback())
                .fpResult(result.feedback().fpFeedback())
                .agentJudgement(result.feedback().agentFeedback())
                .isAuto(false)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();

        detectionRuleRepository.save(rule);
        pendingRuleLogService.pendingRuleLog(rule);

        // Attack detail이 null이 아닌 경우, 저장
        if (result.attackDetail() != null) {
            AttackDetail detail = AttackDetail.builder()
                    .ctiData(ctiData)
                    .attackType(result.attackType())
                    .detail(String.valueOf(result.attackDetail()))
                    .analyzedAt(LocalDateTime.now())
                    .build();

            attackDetailRepository.save(detail);
        }
    }
}
