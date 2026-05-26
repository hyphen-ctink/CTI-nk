package hyphen.ctink.domain.dashboard;

import hyphen.ctink.domain.cti.enums.AttackType;
import hyphen.ctink.domain.dashboard.dto.DetectionReportDTO;
import hyphen.ctink.domain.dashboard.dto.TopRuleDTO;
import hyphen.ctink.domain.indicator.enums.TrustLevel;
import hyphen.ctink.domain.log.ids.IdsDetectionLogRepository;
import hyphen.ctink.domain.log.ids.enums.Result;
import hyphen.ctink.domain.rule.enums.RuleType;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.temporal.TemporalAdjusters;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class DetectionReportService {

    private final IdsDetectionLogRepository idsDetectionLogRepository;

    public DetectionReportDTO getDetectionReport() {
        LocalDate today = LocalDate.now();
        LocalDate monday = today.with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY));
        LocalDate lastWeekStart = monday.minusWeeks(1);
        LocalDate lastWeekEnd = monday.minusDays(1);
        LocalDate twoWeeksStart = monday.minusWeeks(2);
        LocalDate twoWeeksEnd = monday.minusWeeks(1).minusDays(1);

        // Rule Type Result
        List<DetectionReportDTO.RuleTypeResult> ruleTypeResult =
                List.of(
                        countRuleTypeResult(
                                RuleType.SNORT,
                                lastWeekStart,
                                lastWeekEnd,
                                twoWeeksStart,
                                twoWeeksEnd
                        ),
                        countRuleTypeResult(
                                RuleType.YARA,
                                lastWeekStart,
                                lastWeekEnd,
                                twoWeeksStart,
                                twoWeeksEnd
                        )
                );

        // Attack Type Result
        List<DetectionReportDTO.AttackTypeResult> attackTypeResult =
                List.of(
                        countAttackTypeResult(
                                AttackType.RANSOMWARE,
                                lastWeekStart,
                                lastWeekEnd,
                                twoWeeksStart,
                                twoWeeksEnd
                        ),
                        countAttackTypeResult(
                                AttackType.PHISHING,
                                lastWeekStart,
                                lastWeekEnd,
                                twoWeeksStart,
                                twoWeeksEnd
                        ),
                        countAttackTypeResult(
                                AttackType.DDOS,
                                lastWeekStart,
                                lastWeekEnd,
                                twoWeeksStart,
                                twoWeeksEnd
                        ),
                        countAttackTypeResult(
                                AttackType.WEB_ATTACK,
                                lastWeekStart,
                                lastWeekEnd,
                                twoWeeksStart,
                                twoWeeksEnd
                        ),
                        countAttackTypeResult(
                                AttackType.CREDENTIAL_STUFFING,
                                lastWeekStart,
                                lastWeekEnd,
                                twoWeeksStart,
                                twoWeeksEnd
                        ),
                        countAttackTypeResult(
                                AttackType.IOC_ONLY,
                                lastWeekStart,
                                lastWeekEnd,
                                twoWeeksStart,
                                twoWeeksEnd
                        )
                );

        // Top Rules
        List<TopRuleDTO> topRules =
                idsDetectionLogRepository.findTopRules(lastWeekStart.atStartOfDay(), lastWeekEnd.atTime(LocalTime.MAX));

        Map<AttackType, List<TopRuleDTO>> attackTypeGrouped =
                topRules.stream()
                        .collect(Collectors.groupingBy(
                                TopRuleDTO::attackType
                        ));

        List<DetectionReportDTO.TopRulesByAttackType> topRuleByAttackType =
                attackTypeGrouped.entrySet()
                        .stream()
                        .map(entry ->
                                new DetectionReportDTO.TopRulesByAttackType(
                                        entry.getKey(),
                                        entry.getValue()
                                                .stream()
                                                .sorted(
                                                        Comparator.comparingLong(TopRuleDTO::count)
                                                                .reversed()
                                                )
                                                .limit(5)
                                                .map(rule ->
                                                        new DetectionReportDTO.Rules1(
                                                                rule.ruleType(),
                                                                rule.ruleName(),
                                                                rule.count()
                                                        )
                                                )
                                                .toList()
                                )
                        ).toList();

        Map<RuleType, List<TopRuleDTO>> ruleTypeGrouped =
                topRules.stream()
                        .collect(Collectors.groupingBy(
                                TopRuleDTO::ruleType
                        ));

        List<DetectionReportDTO.TopRulesByRuleType> topRuleByRuleType =
                ruleTypeGrouped.entrySet()
                        .stream()
                        .map(entry ->
                                new DetectionReportDTO.TopRulesByRuleType(
                                        entry.getKey(),
                                        entry.getValue()
                                                .stream()
                                                .sorted(
                                                        Comparator.comparingLong(TopRuleDTO::count)
                                                                .reversed()
                                                )
                                                .limit(5)
                                                .map(rule ->
                                                        new DetectionReportDTO.Rules2(
                                                                rule.attackType(),
                                                                rule.ruleName(),
                                                                rule.count()
                                                        )
                                                )
                                                .toList()
                                )
                        ).toList();

        // Date
        List<DetectionReportDTO.Date> date = new ArrayList<>();
        for (LocalDate day = lastWeekStart; !day.isAfter(lastWeekEnd); day = day.plusDays(1)) {
            long count = countDate(day);
            date.add(
                    new DetectionReportDTO.Date(day, count)
            );
        }

        List<DetectionReportDTO.Date> prevDate = new ArrayList<>();
        for (LocalDate day = twoWeeksStart; !day.isAfter(twoWeeksEnd); day = day.plusDays(1)) {
            long count = countDate(day);
            prevDate.add(
                    new DetectionReportDTO.Date(day, count)
            );
        }

        // Trust Level
        List<DetectionReportDTO.CountByTrustLevel> trustLevel =
                List.of(
                        countTrustLevelResult(
                                TrustLevel.HIGH,
                                lastWeekStart,
                                lastWeekEnd,
                                twoWeeksStart,
                                twoWeeksEnd),
                        countTrustLevelResult(
                                TrustLevel.MEDIUM,
                                lastWeekStart,
                                lastWeekEnd,
                                twoWeeksStart,
                                twoWeeksEnd),
                        countTrustLevelResult(
                                TrustLevel.LOW,
                                lastWeekStart,
                                lastWeekEnd,
                                twoWeeksStart,
                                twoWeeksEnd)
                );

        return new DetectionReportDTO(
              lastWeekStart,
              lastWeekEnd,
              twoWeeksStart,
              twoWeeksEnd,
              ruleTypeResult,
              attackTypeResult,
              topRuleByAttackType,
              date,
              prevDate,
              topRuleByRuleType,
              trustLevel
        );
    }

    // Rule Type Result
    private DetectionReportDTO.RuleTypeResult countRuleTypeResult(
            RuleType ruleType,
            LocalDate lastWeekStart,
            LocalDate lastWeekEnd,
            LocalDate twoWeeksStart,
            LocalDate twoWeeksEnd
    ) {
        return new DetectionReportDTO.RuleTypeResult(
                ruleType,
                countRuleType(Result.ALERT, ruleType, lastWeekStart, lastWeekEnd),
                countRuleType(Result.DETECT, ruleType, lastWeekStart, lastWeekEnd),
                countRuleType(Result.BLOCK, ruleType, lastWeekStart, lastWeekEnd),

                countRuleType(Result.ALERT, ruleType, twoWeeksStart, twoWeeksEnd),
                countRuleType(Result.DETECT, ruleType, twoWeeksStart, twoWeeksEnd),
                countRuleType(Result.BLOCK, ruleType, twoWeeksStart, twoWeeksEnd)
        );
    }

    private long countRuleType(
            Result result,
            RuleType ruleType,
            LocalDate start,
            LocalDate end
    ) {
        return idsDetectionLogRepository.countByResultAndDetectionRuleIdRuleTypeAndDetectedAtBetween(
                result, ruleType, start.atStartOfDay(), end.atTime(LocalTime.MAX)
        );
    }

    // Attack Type Result
    private DetectionReportDTO.AttackTypeResult countAttackTypeResult(
            AttackType attackType,
            LocalDate lastWeekStart,
            LocalDate lastWeekEnd,
            LocalDate twoWeeksStart,
            LocalDate twoWeeksEnd
    ) {
        return new DetectionReportDTO.AttackTypeResult(
                attackType,
                countAttackType(attackType, lastWeekStart, lastWeekEnd),
                countAttackType(attackType, twoWeeksStart, twoWeeksEnd)
        );
    }

    private long countAttackType(
            AttackType attackType,
            LocalDate start,
            LocalDate end
    ) {
        return idsDetectionLogRepository.countByDetectionRuleIdAttackTypeAndDetectedAtBetween(
                attackType, start.atStartOfDay(), end.atTime(LocalTime.MAX)
        );
    }

    // Date
    private long countDate(LocalDate day) {
        return idsDetectionLogRepository.countByDetectedAtBetween(
                day.atStartOfDay(),
                day.plusDays(1).atStartOfDay()
        );
    }

    // Trust Level
    private DetectionReportDTO.CountByTrustLevel countTrustLevelResult(
            TrustLevel trustLevel,
            LocalDate lastWeekStart,
            LocalDate lastWeekEnd,
            LocalDate twoWeeksStart,
            LocalDate twoWeeksEnd
    ) {
        return new DetectionReportDTO.CountByTrustLevel(
                trustLevel,
                countTrustLevel(trustLevel, lastWeekStart, lastWeekEnd),
                countTrustLevel(trustLevel, twoWeeksStart, twoWeeksEnd)
        );
    }

    private long countTrustLevel(
            TrustLevel trustLevel,
            LocalDate start,
            LocalDate end
    ) {
        return idsDetectionLogRepository.countByDetectionRuleIdTrustLevelAndDetectedAtBetween(
                trustLevel, start.atStartOfDay(), end.atTime(LocalTime.MAX)
        );
    }
}
