package hyphen.ctink.domain.indicator;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface IocRepository extends JpaRepository<Ioc, Long> {
    List<Ioc> findByIdIn(List<Long> ids);

    Optional<Ioc> findByIocValue(String iocValue);

    Boolean existsByIocValue(String iocValue);

    List<Ioc> findByMispConfirmedFalseOrVirustotalConfirmedFalse();
}
