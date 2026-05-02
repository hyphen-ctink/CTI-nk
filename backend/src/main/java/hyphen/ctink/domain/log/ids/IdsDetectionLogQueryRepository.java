package hyphen.ctink.domain.log.ids;

import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.jpa.impl.JPAQueryFactory;
import hyphen.ctink.domain.cti.enums.AttackType;
import hyphen.ctink.domain.log.ids.dto.IdsLogSearchConditionDTO;
import hyphen.ctink.domain.log.ids.entity.IdsDetectionLog;
import hyphen.ctink.domain.log.ids.enums.Result;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

import static hyphen.ctink.domain.log.ids.entity.QIdsDetectionLog.idsDetectionLog;

@Repository
@RequiredArgsConstructor
public class IdsDetectionLogQueryRepository {
    private final JPAQueryFactory queryFactory;

    public Page<IdsDetectionLog> search(IdsLogSearchConditionDTO cond, Pageable pageable) {
        List<IdsDetectionLog> content = queryFactory
                .selectFrom(idsDetectionLog)
                .where(
                        attackTypeEq(cond.attackType()),
                        resultEq(cond.result()),
                        createdBetween(cond.dateFrom(), cond.dateTo())
                )
                .orderBy(idsDetectionLog.detectedAt.desc())
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .fetch();

        Long total = queryFactory
                .select(idsDetectionLog.count())
                .from(idsDetectionLog)
                .where(
                        attackTypeEq(cond.attackType()),
                        resultEq(cond.result()),
                        createdBetween(cond.dateFrom(), cond.dateTo())
                )
                .fetchOne();

        return new PageImpl<>(content, pageable, total != null ? total : 0);
    }

    private BooleanExpression attackTypeEq(AttackType attackType) {
        return attackType != null ? idsDetectionLog.attackType.eq(attackType) : null;
    }

    private BooleanExpression resultEq(Result result) {
        return result != null ? idsDetectionLog.result.eq(result) : null;
    }

    private BooleanExpression createdBetween(LocalDateTime from, LocalDateTime to) {
        if (from != null && to != null) {
            return idsDetectionLog.detectedAt.between(from, to);
        } else if (from != null) {
            return idsDetectionLog.detectedAt.goe(from);
        } else if (to != null) {
            return idsDetectionLog.detectedAt.loe(to);
        }
        return null;
    }
}
