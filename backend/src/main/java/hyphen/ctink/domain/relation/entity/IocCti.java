package hyphen.ctink.domain.relation.entity;

import hyphen.ctink.domain.cti.entity.CtiData;
import hyphen.ctink.domain.indicator.Ioc;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "ioc_cti")
public class IocCti {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "cti_id", nullable = false)
    private CtiData cti;

    @ManyToOne
    @JoinColumn(name = "ioc_id", nullable = false)
    private Ioc ioc;
}
