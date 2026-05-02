package hyphen.ctink.domain.log.notification.entity;

import hyphen.ctink.domain.log.notification.enums.Decision;
import hyphen.ctink.domain.log.notification.enums.NotificationType;
import hyphen.ctink.domain.user.User;
import hyphen.ctink.domain.rule.enums.RuleType;
import hyphen.ctink.domain.rule.entity.DetectionRule;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@Entity
@Table(name = "notification_log")
public class NotificationLog {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "notification_type", nullable = false)
    @Enumerated(EnumType.STRING)
    private NotificationType notificationType;

    @Column(name = "rule_type")
    @Enumerated(EnumType.STRING)
    private RuleType ruleType;

    @ManyToOne
    @JoinColumn(name = "target_user_id", nullable = false)
    private User user;

    @ManyToOne
    @JoinColumn(name = "rule_id")
    private DetectionRule detectionRule;

    @Column(name = "suspected_type")
    private String suspectedType;

    @Column(name = "is_sent", nullable = false)
    private Boolean isSent;

    @Enumerated(EnumType.STRING)
    private Decision decision;

    @Column(name = "is_applied")
    private Boolean isApplied;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "responded_at")
    private LocalDateTime respondedAt;
}
