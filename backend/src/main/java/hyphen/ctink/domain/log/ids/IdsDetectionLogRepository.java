package hyphen.ctink.domain.log.ids;

import hyphen.ctink.domain.cti.enums.AttackType;
import hyphen.ctink.domain.dashboard.dto.DetectionReportDTO;
import hyphen.ctink.domain.dashboard.dto.TopRuleDTO;
import hyphen.ctink.domain.indicator.enums.TrustLevel;
import hyphen.ctink.domain.log.ids.entity.IdsDetectionLog;
import hyphen.ctink.domain.log.ids.enums.Result;
import hyphen.ctink.domain.rule.enums.RuleType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

public interface IdsDetectionLogRepository extends JpaRepository<IdsDetectionLog, Long> {
    long countByResult(Result result);

    long countByResultAndDetectionRuleIdRuleTypeAndDetectedAtBetween(
            Result result, RuleType ruleType, LocalDateTime start, LocalDateTime end
    );

    long countByDetectionRuleIdAttackTypeAndDetectedAtBetween(
            AttackType attackType, LocalDateTime start, LocalDateTime end
    );

    long countByDetectedAtBetween(LocalDateTime start, LocalDateTime end);

    long countByDetectionRuleIdTrustLevelAndDetectedAtBetween(
            TrustLevel trustLevel, LocalDateTime start, LocalDateTime end
    );

    @Query("""
        select new hyphen.ctink.domain.dashboard.dto.TopRuleDTO(
            l.detectionRuleId.attackType,
            l.detectionRuleId.ruleType,
            l.detectionRuleId.ruleName,
            count(1)
        )
        from IdsDetectionLog l
        where l.detectedAt between :start and :end
        group by
            l.detectionRuleId.id
        order by count(1) desc
    """)
    List<TopRuleDTO> findTopRules(
            @Param("start") LocalDateTime start,
            @Param("end") LocalDateTime end
    );
}
