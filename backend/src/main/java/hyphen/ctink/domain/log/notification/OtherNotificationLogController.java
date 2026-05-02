package hyphen.ctink.domain.log.notification;

import hyphen.ctink.domain.log.notification.dto.OtherNotificationResponseDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/ctink/notifications/other-threat")
public class OtherNotificationLogController {
    private final OtherNotificationLogService otherNotificationLogService;

    @GetMapping
    public OtherNotificationResponseDTO getOtherNotificationLogs(
            @RequestParam(required = false) Integer page
    ) {
        return otherNotificationLogService.getOtherNotificationLog(page);
    }
}
