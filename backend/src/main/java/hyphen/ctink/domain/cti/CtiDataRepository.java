package hyphen.ctink.domain.cti;

import hyphen.ctink.domain.cti.entity.CtiData;
import hyphen.ctink.domain.dashboard.dto.AttackTypeDistributionDTO;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface CtiDataRepository extends JpaRepository<CtiData, Long> {
    long countByCollectedAtBetween(LocalDateTime start, LocalDateTime end);

    List<CtiData> findTop10ByOrderByCollectedAtDesc();

    @Query("""
        SELECT new hyphen.ctink.domain.dashboard.dto.AttackTypeDistributionDTO(
            c.attackType,
            COUNT(c)
        )
        FROM CtiData c
        WHERE c.collectedAt BETWEEN :start AND :end
        GROUP BY c.attackType
    """)
    List<AttackTypeDistributionDTO> countAttackTypeByPeriod(
            @Param("start") LocalDateTime start,
            @Param("end") LocalDateTime end
    );
}
