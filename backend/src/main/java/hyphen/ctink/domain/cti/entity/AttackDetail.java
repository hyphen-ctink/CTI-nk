package hyphen.ctink.domain.cti.entity;

import java.time.LocalDateTime;

import hyphen.ctink.domain.cti.enums.AttackType;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "attack_detail")
public class AttackDetail {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "cti_id", nullable = false)
    private CtiData ctiData;

    @Column(name = "attack_type", nullable = false)
    @Enumerated(EnumType.STRING)
    private AttackType attackType;

    @Column(columnDefinition = "JSON")
    private String detail;

    @Column(name = "analyzed_at", nullable = false)
    private LocalDateTime analyzedAt;
}
