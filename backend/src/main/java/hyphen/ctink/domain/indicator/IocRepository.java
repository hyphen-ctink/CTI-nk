package hyphen.ctink.domain.indicator;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface IocRepository extends JpaRepository<Ioc, Long> {
    Optional<Ioc> findByIocValue(String iocValue);

    Boolean existsByIocValue(String iocValue);

    List<Ioc> findByMispConfirmedFalseOrVirustotalConfirmedFalse();

    @Query("""
        select i
        from Ioc i
        where i.cti.id = :ctiId
    """)
    List<Ioc> findByCtiId(@Param("ctiId") Long ctiId);
}
