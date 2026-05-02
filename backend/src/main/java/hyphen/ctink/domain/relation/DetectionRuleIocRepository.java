package hyphen.ctink.domain.relation;

import hyphen.ctink.domain.relation.entity.DetectionRuleIoc;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface DetectionRuleIocRepository extends JpaRepository<DetectionRuleIoc, Long> {
    @Query("""
    SELECT dri.detectionRule.id
    FROM DetectionRuleIoc dri
    WHERE dri.ioc.id IN :iocIds
    """)
    List<Long> findRuleIdsByIocIds(@Param("iocIds") List<Long> iocIds);
}
