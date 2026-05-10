package hyphen.ctink.domain.log.system;

import hyphen.ctink.domain.log.system.entity.SystemLog;
import hyphen.ctink.domain.log.system.enums.LogStatus;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SystemLogRepository extends JpaRepository<SystemLog, Long> {
    long countByLogStatus(LogStatus status);
}
