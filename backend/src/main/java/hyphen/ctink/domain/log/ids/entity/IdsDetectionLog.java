package hyphen.ctink.domain.log.ids.entity;

import hyphen.ctink.domain.cti.enums.AttackType;
import hyphen.ctink.domain.log.ids.enums.Result;
import hyphen.ctink.domain.rule.entity.DetectionRule;
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
