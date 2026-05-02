package hyphen.ctink.domain.relation;

import hyphen.ctink.domain.relation.entity.IocCti;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface IocCtiRepository extends JpaRepository<IocCti, Long> {
    @Query("""
    SELECT ic.ioc.id
    FROM IocCti ic
    WHERE ic.cti.id = :ctiId
    """)
    List<Long> findIocIdsByCtiId(@Param("ctiId") Long ctiId);
}
