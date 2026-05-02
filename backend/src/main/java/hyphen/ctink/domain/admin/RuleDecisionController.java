package hyphen.ctink.domain.admin;

import hyphen.ctink.domain.log.notification.enums.Decision;
import hyphen.ctink.domain.admin.dto.RuleDecisionRequestDTO;
import hyphen.ctink.domain.admin.dto.RuleDecisionResponseDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/ctink/admin/rules")
public class RuleDecisionController {

    private final RuleDecisionService ruleDecisionService;

    @PatchMapping("/{ruleId}/decision")
    public RuleDecisionResponseDTO decideRule(
            @PathVariable Long ruleId,
            @RequestBody RuleDecisionRequestDTO req
            ) {
        Decision decision = ruleDecisionService.decideRule(ruleId, req);
        return new RuleDecisionResponseDTO(decision.getMessage());
    }
}
