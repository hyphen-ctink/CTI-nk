package hyphen.ctink.domain.log.ids.entity;

import hyphen.ctink.domain.cti.enums.AttackType;
import hyphen.ctink.domain.log.ids.enums.Result;
import hyphen.ctink.domain.rule.entity.DetectionRule;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@Entity
@Table(name = "ids_detection_log")
public class IdsDetectionLog {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "rule_id", nullable = false)
    private DetectionRule detectionRule;

    @Column(name = "attack_type")
    @Enumerated(EnumType.STRING)
    private AttackType attackType;

    @Column(columnDefinition = "TEXT")
    private String detail;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private Result result;

    @Column(name = "detected_at", nullable = false)
    private LocalDateTime detectedAt;
}
