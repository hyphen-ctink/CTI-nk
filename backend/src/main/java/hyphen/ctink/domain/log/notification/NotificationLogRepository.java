package hyphen.ctink.domain.log.notification;

import hyphen.ctink.domain.log.notification.entity.NotificationLog;
import hyphen.ctink.domain.log.notification.enums.Decision;
import hyphen.ctink.domain.log.notification.enums.NotificationType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;

public interface NotificationLogRepository extends JpaRepository<NotificationLog, Long> {
    Page<NotificationLog> findByNotificationType(
            NotificationType type,
            Pageable pageable
    );

    @Modifying
    @Query("""
        UPDATE NotificationLog n
        SET n.decision = :decision,
            n.respondedAt = :respondedAt
        WHERE n.detectionRule.id = :ruleId
    """)
    int updateDecision(
            @Param("ruleId") Long ruleId,
            @Param("decision") Decision decision,
            @Param("respondedAt") LocalDateTime respondedAt
    );
}
