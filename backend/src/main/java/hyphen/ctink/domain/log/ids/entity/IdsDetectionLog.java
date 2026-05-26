package hyphen.ctink.domain.log.ids.entity;

import hyphen.ctink.domain.cti.enums.AttackType;
import hyphen.ctink.domain.log.ids.enums.Result;
import hyphen.ctink.domain.rule.entity.DetectionRule;
import hyphen.ctink.domain.rule.enums.RuleType;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Getter
@Setter
@Builder
@Entity
@Table(name = "ids_detection_log")
@NoArgsConstructor
@AllArgsConstructor
public class IdsDetectionLog {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "detection_rule_id", nullable = false)
    private DetectionRule detectionRuleId;

    @Column(columnDefinition = "TEXT")
    private String detail;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private Result result;

    @Column(name = "detected_at", nullable = false)
    private LocalDateTime detectedAt;
}
