package hyphen.ctink.domain.indicator;

import hyphen.ctink.domain.cti.CtiPlatformConverter;
import hyphen.ctink.domain.cti.entity.CtiData;
import hyphen.ctink.domain.cti.enums.CtiPlatform;
import hyphen.ctink.domain.indicator.enums.IoCStatus;
import hyphen.ctink.domain.indicator.enums.IocType;
import hyphen.ctink.domain.indicator.enums.TrustLevel;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.Set;

@Getter
@Setter
@Entity
@Builder
@Table(name = "ioc")
@NoArgsConstructor
@AllArgsConstructor
public class Ioc {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "cti_id", nullable = false)
    private CtiData cti;

    @Convert(converter = CtiPlatformConverter.class)
    @Column(name = "platform_name")
    private Set<CtiPlatform> platformName;

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

    public void updateTrustLevel(TrustLevel trustLevel) {
        this.trustLevel = trustLevel;
    }

    public void updateMispConfirmed(Boolean confirmed) {
        this.mispConfirmed = confirmed;
    }

    public void updateVirustotalConfirmed(Boolean confirmed) {
        this.virustotalConfirmed = confirmed;
    }
}
