package hyphen.ctink.domain.indicator;

import hyphen.ctink.domain.cti.CtiDataRepository;
import hyphen.ctink.domain.cti.entity.CtiData;
import hyphen.ctink.domain.cti.enums.CtiPlatform;
import hyphen.ctink.domain.indicator.enums.TrustLevel;
import hyphen.ctink.domain.log.notification.NotificationLogRepository;
import hyphen.ctink.domain.log.notification.entity.NotificationLog;
import hyphen.ctink.domain.rule.DetectionRuleRepository;
import hyphen.ctink.domain.rule.entity.DetectionRule;
import hyphen.ctink.domain.rule.enums.RuleStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class UpdateTrustLevelService {

    private final IocRepository iocRepository;
    private final DetectionRuleRepository detectionRuleRepository;
    private final NotificationLogRepository notificationLogRepository;

    @Transactional
    public void updateTrustLevel(Long iocId) {
        Ioc ioc = iocRepository.findById(iocId)
                .orElseThrow(() -> new RuntimeException("Ioc not found"));

        Set<CtiPlatform> platforms = ioc.getPlatformName();

        Long ctiId = ioc.getCti().getId();

        int platformCount = (platforms == null) ? 0 : platforms.size();

        if (platformCount < 3) {
            if (ioc.isMispConfirmed() && ioc.isVirustotalConfirmed()) {
                ioc.setTrustLevel(TrustLevel.HIGH);
                updateDetectionRule(ctiId, TrustLevel.HIGH);
            } else if (ioc.isMispConfirmed() || ioc.isVirustotalConfirmed()) {
                ioc.setTrustLevel(TrustLevel.MEDIUM);
                updateDetectionRule(ctiId, TrustLevel.MEDIUM);
            } else {
                ioc.setTrustLevel(TrustLevel.LOW);
                updateDetectionRule(ctiId, TrustLevel.LOW);
            }
        } else {
            if (ioc.isMispConfirmed() || ioc.isVirustotalConfirmed()) {
                ioc.setTrustLevel(TrustLevel.HIGH);
                updateDetectionRule(ctiId, TrustLevel.HIGH);
            } else {
                ioc.setTrustLevel(TrustLevel.MEDIUM);
                updateDetectionRule(ctiId, TrustLevel.MEDIUM);
            }
        }
    }

    @Transactional
    public void updateDetectionRule(Long ctiId, TrustLevel trustLevel) {
        List<DetectionRule> rules = detectionRuleRepository.findByCtiId(ctiId);

        for (DetectionRule rule : rules) {
            rule.updateTruestLevel(trustLevel);

            if (trustLevel != TrustLevel.LOW) {
                rule.updateStatus(RuleStatus.ACTIVE);

                NotificationLog log = notificationLogRepository.findByDetectionRule(rule);
                if (log != null) {
                    notificationLogRepository.delete(log);
                }
            }
        }
    }
}
