package hyphen.ctink.domain.rule.entity;

import hyphen.ctink.domain.cti.enums.AttackType;
import hyphen.ctink.domain.cti.entity.CtiData;

import java.time.LocalDateTime;

import hyphen.ctink.domain.indicator.enums.TrustLevel;
import hyphen.ctink.domain.rule.enums.OsType;
import hyphen.ctink.domain.rule.enums.RuleStatus;
import hyphen.ctink.domain.rule.enums.RuleType;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "detection_rule")
public class DetectionRule {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "cti_id", nullable = false)
    private CtiData cti;

    @Column(name = "rule_name", nullable = false)
    private String ruleName;

    @Column(name = "rule_type", nullable = false)
    @Enumerated(EnumType.STRING)
    private RuleType ruleType;

    @Column(name = "os_type")
    @Enumerated(EnumType.STRING)
    private OsType osType;

    @Column(name = "rule_content", columnDefinition = "TEXT", nullable = false)
    private String ruleContent;

    @Column(name = "attack_type")
    @Enumerated(EnumType.STRING)
    private AttackType attackType;

    @Column(name = "trust_level")
    @Enumerated(EnumType.STRING)
    private TrustLevel trustLevel;

    @Column(nullable = false)
    private int version;

    @Column(name = "regen_count", nullable = false)
    private int regenCount;

    @Column(name = "rule_status", nullable = false)
    @Enumerated(EnumType.STRING)
    private RuleStatus ruleStatus;

    @Column(name = "grammar_result", columnDefinition = "JSON")
    private String grammarResult;

    @Column(name = "fn_result", columnDefinition = "JSON")
    private String fnResult;

    @Column(name = "fp_result", columnDefinition = "JSON")
    private String fpResult;

    @Column(name = "agent_judgement", columnDefinition = "TEXT")
    private String agentJudgement;

    @Column(name = "is_auto")
    private Boolean isAuto;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    public void updateStatus(RuleStatus status) {
        this.ruleStatus = status;
    }

    public void updateTruestLevel(TrustLevel level) {
        this.trustLevel = level;
    }
}
