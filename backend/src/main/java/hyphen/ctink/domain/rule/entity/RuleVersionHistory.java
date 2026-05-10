package hyphen.ctink.domain.rule.entity;

import hyphen.ctink.domain.rule.enums.ChangeReason;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@Entity
@Table(name = "rule_version_history")
public class RuleVersionHistory {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "rule_id", nullable = false)
    private DetectionRule detectionRule;

    @Column(nullable = false)
    private int version;

    @Column(name = "rule_content", nullable = false)
    private String ruleContent;

    @Column(name = "change_reason", nullable = false)
    @Enumerated(EnumType.STRING)
    private ChangeReason changeReason;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;
}
