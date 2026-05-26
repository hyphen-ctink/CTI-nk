package hyphen.ctink.domain.cti.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Getter
@Setter
@Builder
@Entity
@Table(name = "other_threat")
@AllArgsConstructor
@NoArgsConstructor
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
