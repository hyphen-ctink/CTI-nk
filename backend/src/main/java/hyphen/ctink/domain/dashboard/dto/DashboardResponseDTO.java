package hyphen.ctink.domain.dashboard.dto;

import java.util.List;

public record DashboardResponseDTO(
        long threatCount,
        long threatCountDiff,
        long ruleCount,
        long ruleCountDiff,
        long pendingCount,
        List<PlatformStatusDTO> platformStatus,
        List<RecentThreatDTO> recentThreats,
        List<AttackTypeDistributionDTO> attackTypeDistribution
) {}
