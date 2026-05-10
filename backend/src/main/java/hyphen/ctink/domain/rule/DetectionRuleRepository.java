package hyphen.ctink.domain.rule;

import hyphen.ctink.domain.rule.entity.DetectionRule;
import hyphen.ctink.domain.rule.enums.RuleStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface DetectionRuleRepository extends JpaRepository<DetectionRule, Long> {
    long countByCreatedAtBetween(LocalDateTime start, LocalDateTime end);

    long countByRuleStatus(RuleStatus status);

    long count();

    List<DetectionRule> findByIdIn(List<Long> ids);

    @Query("SELECT r.ruleStatus FROM DetectionRule r WHERE r.id = :ruleId")
    RuleStatus findRuleStatusById(@Param("ruleId") Long ruleId);
}
