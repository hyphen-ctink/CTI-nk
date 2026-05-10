package hyphen.ctink.domain.indicator;

import hyphen.ctink.domain.indicator.enums.IoCStatus;
import hyphen.ctink.domain.indicator.enums.IocType;
import hyphen.ctink.domain.indicator.enums.TrustLevel;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@Entity
@Table(name = "ioc")
public class Ioc {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // platform_name

    @Column(name = "ioc_type")
    @Enumerated(EnumType.STRING)
    private IocType iocType;

    @Column(name = "ioc_value", nullable = false)
    private String iocValue;

    @Column(name = "virustotal_confirmed", nullable = false)
    private boolean virustotalConfirmed;

    @Column(name = "misp_confirmed", nullable = false)
    private boolean mispConfirmed;

    @Column(name = "trust_level")
    @Enumerated(EnumType.STRING)
    private TrustLevel trustLevel;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "ioc_status")
    @Enumerated(EnumType.STRING)
    private IoCStatus ioCStatus;
}
