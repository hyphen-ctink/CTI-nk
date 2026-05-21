package hyphen.ctink.domain.cti.entity;

import hyphen.ctink.domain.cti.enums.AttackType;
import hyphen.ctink.domain.cti.enums.ProcessStatus;
import hyphen.ctink.domain.platform.CollectionPlatform;
import jakarta.persistence.*;
import java.time.LocalDateTime;

import lombok.*;

@Getter
@Setter
@Entity
@Builder
@Table(name = "cti_data")
@NoArgsConstructor
@AllArgsConstructor
public class CtiData {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "platform_id", nullable = false)
    private CollectionPlatform collectionPlatform;

    @Column(name = "summary_title")
    private String summaryTitle;

    @Column(name = "summary_content", columnDefinition = "TEXT")
    private String summaryContent;

    @Column(name = "source_url")
    private String sourceUrl;

    @Column(name = "raw_data", columnDefinition = "TEXT")
    private String rawData;

    @Column(name = "attack_type")
    @Enumerated(EnumType.STRING)
    private AttackType attackType;

    @Column(name = "process_status", nullable = false)
    @Enumerated(EnumType.STRING)
    private ProcessStatus processStatus;

    @Column(name = "collected_at", nullable = false)
    private LocalDateTime collectedAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    public void updateSummaryTitle(String title) {
        this.summaryTitle = title;
    }

    public void updateAnalysisResult(String content, AttackType attackType) {
        this.summaryContent = content;
        this.attackType = attackType;
        this.processStatus = ProcessStatus.PROCESSING;
        this.updatedAt = LocalDateTime.now();
    }

    public void updateAttackType(AttackType attackType) {
        this.attackType = attackType;
    }

    public void updateProcessStatus(ProcessStatus status) {
        this.processStatus = status;
    }
}
