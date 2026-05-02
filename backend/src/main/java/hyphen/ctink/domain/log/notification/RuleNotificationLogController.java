package hyphen.ctink.domain.log.notification;

import hyphen.ctink.domain.log.notification.dto.RuleNotificationRequestDTO;
import hyphen.ctink.domain.log.notification.dto.RuleNotificationResponseDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/ctink/notifications/rules/pending")
public class RuleNotificationLogController {
    private final RuleNotificationLogService ruleNotificationLogService;

    @GetMapping
    public RuleNotificationResponseDTO getRuleNotificationLogs(RuleNotificationRequestDTO req) {
        return ruleNotificationLogService.getRuleNotificationLog(req);
    }
}
