package hyphen.ctink.domain.admin.dto;

import hyphen.ctink.domain.log.notification.enums.Decision;
import lombok.Getter;

@Getter
public class RuleDecisionRequestDTO {
    private Decision decision;
}
