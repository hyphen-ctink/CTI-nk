package hyphen.ctink.domain.rule;

import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.jpa.impl.JPAQueryFactory;
import hyphen.ctink.domain.cti.enums.AttackType;
import hyphen.ctink.domain.indicator.enums.TrustLevel;
import hyphen.ctink.domain.rule.dto.RuleSearchConditionDTO;
import hyphen.ctink.domain.rule.entity.DetectionRule;
import hyphen.ctink.domain.rule.enums.RuleStatus;
import hyphen.ctink.domain.rule.enums.RuleType;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

import static hyphen.ctink.domain.rule.entity.QDetectionRule.detectionRule;

@Repository
@RequiredArgsConstructor
public class RuleQueryRepository {
    private final JPAQueryFactory queryFactory;

    public Page<DetectionRule> search(RuleSearchConditionDTO cond, Pageable pageable) {
        List<DetectionRule> content = queryFactory
                .selectFrom(detectionRule)
                .where(
                        keywordContains(cond.search()),
                        ruleTypeEq(cond.ruleType()),
                        attackTypeEq(cond.attackType()),
                        trustLevelEq(cond.trustLevel()),
                        statusEq(cond.status()),
                        createdBetween(cond.dateFrom(), cond.dateTo())
                )
                .orderBy(detectionRule.createdAt.desc())
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .fetch();

        Long total = queryFactory
                .select(detectionRule.count())
                .from(detectionRule)
                .where(
                        keywordContains(cond.search()),
                        ruleTypeEq(cond.ruleType()),
                        attackTypeEq(cond.attackType()),
                        trustLevelEq(cond.trustLevel()),
                        statusEq(cond.status()),
                        createdBetween(cond.dateFrom(), cond.dateTo())
                )
                .fetchOne();

        return new PageImpl<>(content, pageable, total != null ? total : 0);
    }

    private BooleanExpression keywordContains(String keyword) {
        return keyword != null ? detectionRule.ruleName.contains(keyword) : null;
    }

    private BooleanExpression ruleTypeEq(RuleType ruleType) {
        return ruleType != null ? detectionRule.ruleType.eq(ruleType) : null;
    }

    private BooleanExpression attackTypeEq(AttackType attackType) {
        return attackType != null ? detectionRule.attackType.eq(attackType) : null;
    }

    private BooleanExpression trustLevelEq(TrustLevel trustLevel) {
        return trustLevel != null ? detectionRule.trustLevel.eq(trustLevel) : null;
    }

    private BooleanExpression statusEq(RuleStatus status) {
        return status != null ? detectionRule.ruleStatus.eq(status) : null;
    }

    private BooleanExpression createdBetween(LocalDateTime from, LocalDateTime to) {
        if (from != null && to != null) {
            return detectionRule.createdAt.between(from, to);
        } else if (from != null) {
            return detectionRule.createdAt.goe(from);
        } else if (to != null) {
            return detectionRule.createdAt.loe(to);
        }
        return null;
    }
}
