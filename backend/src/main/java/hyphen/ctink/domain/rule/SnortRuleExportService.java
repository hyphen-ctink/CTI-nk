package hyphen.ctink.domain.rule;

import hyphen.ctink.domain.indicator.enums.TrustLevel;
import hyphen.ctink.domain.log.notification.NotificationLogRepository;
import hyphen.ctink.domain.log.notification.entity.NotificationLog;
import hyphen.ctink.domain.log.system.SystemLogRepository;
import hyphen.ctink.domain.log.system.entity.SystemLog;
import hyphen.ctink.domain.log.system.enums.LogStatus;
import hyphen.ctink.domain.log.system.enums.Stage;
import hyphen.ctink.domain.rule.entity.DetectionRule;
import hyphen.ctink.domain.rule.enums.RuleStatus;
import hyphen.ctink.domain.rule.enums.RuleType;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class SnortRuleExportService {

    private final DetectionRuleRepository detectionRuleRepository;
    private final SystemLogRepository systemLogRepository;
    private final NotificationLogRepository notificationLogRepository;

    @Value("${snort.rule.path}")
    private String rulePath;

    @Scheduled(cron = "0 0 * * * *")
    @Transactional
    public void exportRules() throws IOException {
        List<DetectionRule> rules = detectionRuleRepository.findByRuleType(RuleType.SNORT);

        StringBuilder sb = new StringBuilder();
        for (DetectionRule rule : rules) {
            if (rule.getRuleStatus() == RuleStatus.ACTIVE || rule.getTrustLevel() != TrustLevel.LOW) {
                sb.append(rule.getRuleContent())
                        .append(System.lineSeparator())
                        .append("\n");

                if (!systemLogRepository.existsByDetectionRuleId(rule.getId())) {
                    SystemLog log = SystemLog.builder()
                            .createdAt(LocalDateTime.now())
                            .logStatus(LogStatus.SUCCESS)
                            .message("Detection Rule Applied (" + rule.getRuleContent() + ")")
                            .stage(Stage.APPLY)
                            .detectionRule(rule)
                            .build();

                    systemLogRepository.save(log);
                }

                NotificationLog notificationLog = notificationLogRepository.findByDetectionRule(rule);
                if (notificationLog != null) {
                    notificationLog.updateIsApplied(true);
                }
            }
        }

        Path path = Paths.get(rulePath);
        Files.createDirectories(path.getParent());
        Files.writeString(
                path,
                sb.toString(),
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING
        );
    }
}
