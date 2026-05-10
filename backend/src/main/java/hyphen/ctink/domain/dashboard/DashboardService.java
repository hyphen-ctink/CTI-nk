package hyphen.ctink.domain.dashboard;

import hyphen.ctink.domain.cti.CtiDataRepository;
import hyphen.ctink.domain.dashboard.dto.AttackTypeDistributionDTO;
import hyphen.ctink.domain.dashboard.dto.DashboardResponseDTO;
import hyphen.ctink.domain.dashboard.dto.PlatformStatusDTO;
import hyphen.ctink.domain.dashboard.dto.RecentThreatDTO;
import hyphen.ctink.domain.platform.CollectionPlatformRepository;
import hyphen.ctink.domain.rule.DetectionRuleRepository;
import hyphen.ctink.domain.rule.enums.RuleStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class DashboardService {
    private final CtiDataRepository ctiDataRepository;
    private final CollectionPlatformRepository collectionPlatformRepository;
    private final DetectionRuleRepository detectionRuleRepository;

    public DashboardResponseDTO getDashboard() {
        LocalDateTime end = LocalDateTime.now();
        LocalDateTime start = end.minusDays(7);

        // threat_count
        long thisWeekThreatCount = ctiDataRepository.countByCollectedAtBetween(start, end);
        long lastWeekThreatCount = ctiDataRepository.countByCollectedAtBetween(start.minusDays(7), start);
        long threatCountDiff = thisWeekThreatCount - lastWeekThreatCount;

        // rule_count
        long thisWeekRuleCount = detectionRuleRepository.countByCreatedAtBetween(start, end);
        long lastWeekRuleCount = detectionRuleRepository.countByCreatedAtBetween(start.minusDays(7), start);
        long ruleCountDiff = thisWeekRuleCount - lastWeekRuleCount;

        // pending_count
        long pendingCount = detectionRuleRepository.countByRuleStatus(RuleStatus.PENDING);

        // platform_status
        List<PlatformStatusDTO> platformStatus =
                collectionPlatformRepository.findAll()
                        .stream()
                        .map(PlatformStatusDTO::from)
                        .toList();

        // recent_threats
        List<RecentThreatDTO> recentThreat =
                ctiDataRepository.findTop10ByOrderByCollectedAtDesc()
                        .stream()
                        .map(RecentThreatDTO::from)
                        .toList();

        // attack_type_distribution
        List<AttackTypeDistributionDTO> attackTypeDistribution =
                ctiDataRepository.countAttackTypeByPeriod(start, end);

        return new DashboardResponseDTO(
                thisWeekThreatCount,
                threatCountDiff,
                thisWeekRuleCount,
                ruleCountDiff,
                pendingCount,
                platformStatus,
                recentThreat,
                attackTypeDistribution
        );
    }
}
