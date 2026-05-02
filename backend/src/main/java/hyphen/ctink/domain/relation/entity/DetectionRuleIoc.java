package hyphen.ctink.domain.relation.entity;

import hyphen.ctink.domain.indicator.Ioc;
import hyphen.ctink.domain.rule.entity.DetectionRule;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "detection_rule_ioc")
public class DetectionRuleIoc {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "rule_id", nullable = false)
    private DetectionRule detectionRule;

    @ManyToOne
    @JoinColumn(name = "ioc_id", nullable = false)
    private Ioc ioc;
}
