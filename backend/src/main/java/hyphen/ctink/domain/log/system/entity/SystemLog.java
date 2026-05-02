package hyphen.ctink.domain.log.system.entity;

import hyphen.ctink.domain.cti.entity.CtiData;
import hyphen.ctink.domain.log.system.enums.LogStatus;
import hyphen.ctink.domain.log.system.enums.Stage;
import hyphen.ctink.domain.rule.entity.DetectionRule;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@Entity
@Table(name = "system_log")
public class SystemLog {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private Stage stage;

    @ManyToOne
    @JoinColumn(name = "cti_id")
    private CtiData ctiData;

    @ManyToOne
    @JoinColumn(name = "rule_id")
    private DetectionRule detectionRule;

    @Column(name = "log_status", nullable = false)
    @Enumerated(EnumType.STRING)
    private LogStatus logStatus;

    @Column(columnDefinition = "TEXT")
    private String message;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;
}
