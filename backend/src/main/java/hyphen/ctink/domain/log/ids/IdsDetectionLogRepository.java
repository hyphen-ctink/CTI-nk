package hyphen.ctink.domain.log.ids;

import hyphen.ctink.domain.log.ids.entity.IdsDetectionLog;
import hyphen.ctink.domain.log.ids.enums.Result;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IdsDetectionLogRepository extends JpaRepository<IdsDetectionLog, Long> {
    long countByResult(Result result);
}
