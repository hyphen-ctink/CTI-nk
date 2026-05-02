package hyphen.ctink.domain.rule;

import hyphen.ctink.domain.rule.dto.DetectionRuleDetailResponseDTO;
import hyphen.ctink.domain.rule.dto.DetectionRuleRequestDTO;
import hyphen.ctink.domain.rule.dto.DetectionRuleResponseDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/ctink/rules")
public class DetectionRuleController {
    private final DetectionRuleService detectionRuleService;
    private final DetectionRuleDetailService detectionRuleDetailService;

    @GetMapping
    public DetectionRuleResponseDTO getRules(DetectionRuleRequestDTO req) {
        return detectionRuleService.getRule(req);
    }

    @GetMapping("/{ruleId}")
    public DetectionRuleDetailResponseDTO getRuleDetail(@PathVariable Integer ruleId) {
        return detectionRuleDetailService.getRuleDetail(ruleId);
    }
}
