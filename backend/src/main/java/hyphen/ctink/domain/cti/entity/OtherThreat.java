package hyphen.ctink.domain.cti.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@Entity
@Table(name = "other_threat")
public class OtherThreat {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "cti_id", nullable = false)
    private CtiData ctiData;

    @Column(name = "suspected_type")
    private String suspectedType;

    @Column(name = "analyzed_at", nullable = false)
    private LocalDateTime analyzedAt;
}
