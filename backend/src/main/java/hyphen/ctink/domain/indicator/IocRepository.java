package hyphen.ctink.domain.indicator;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface IocRepository extends JpaRepository<Ioc, Long> {
    List<Ioc> findByIdIn(List<Long> ids);
}
