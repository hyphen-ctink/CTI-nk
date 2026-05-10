package hyphen.ctink.domain.log.notification;

import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.jpa.impl.JPAQueryFactory;
import hyphen.ctink.domain.log.notification.entity.NotificationLog;
import hyphen.ctink.domain.rule.enums.RuleType;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;

import java.util.List;

import static hyphen.ctink.domain.log.notification.entity.QNotificationLog.notificationLog;

@Repository
@RequiredArgsConstructor
public class RuleNotificationLogQueryRepository {
    private final JPAQueryFactory queryFactory;

    public Page<NotificationLog> search(RuleType ruleType, Pageable pageable) {
        List<NotificationLog> content = queryFactory
                .selectFrom(notificationLog)
                .where(
                    ruleTypeEq(ruleType)
                )
                .orderBy(notificationLog.createdAt.desc())
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .fetch();

        Long total = queryFactory
                .select(notificationLog.count())
                .from(notificationLog)
                .where(
                        ruleTypeEq(ruleType)
                )
                .fetchOne();

        return new PageImpl<>(content, pageable, total != null ? total : 0);
    }

    private BooleanExpression ruleTypeEq(RuleType ruleType) {
        return ruleType != null ? notificationLog.ruleType.eq(ruleType) : null;
    }
}
