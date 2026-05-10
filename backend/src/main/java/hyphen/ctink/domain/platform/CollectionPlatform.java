package hyphen.ctink.domain.platform;

import hyphen.ctink.domain.cti.enums.CollectMethod;
import jakarta.persistence.*;
import java.time.LocalDateTime;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "collection_platform")
public class CollectionPlatform {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    @Column(name = "collect_method", nullable = false)
    @Enumerated(EnumType.STRING)
    private CollectMethod collectMethod;

    @Column(name = "is_ioc_only", nullable = false)
    private boolean isIoCOnly;

    @Column(name = "last_commit_sha")
    private String lastCommitSha;

    @Column(name = "current_interval_time", nullable = false)
    private int currentIntervalTime;

    @Column(name = "valid_ioc_count", nullable = false)
    private int validIoCCount;

    @Column(name = "cycle_reset_at")
    private LocalDateTime cycleResetAt;

    @Column(name = "last_collected_at")
    private LocalDateTime lastCollectedAt;
}
