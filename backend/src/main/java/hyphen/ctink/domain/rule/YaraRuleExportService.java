package hyphen.ctink.domain.rule;

import hyphen.ctink.domain.rule.entity.DetectionRule;
import hyphen.ctink.domain.rule.enums.RuleType;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.List;

@Service
@RequiredArgsConstructor
public class YaraRuleExportService {

    private final DetectionRuleRepository detectionRuleRepository;

    @Value("${yara.rule.path}")
    private String rulePath;

    @Scheduled(cron = "0 0 0 * * *")
    public void exportRules() throws IOException {
        List<DetectionRule> rules = detectionRuleRepository.findByRuleType(RuleType.YARA);

        StringBuilder sb = new StringBuilder();
        for (DetectionRule rule : rules) {
            sb.append(rule.getRuleContent())
                    .append(System.lineSeparator())
                    .append("\n");
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
