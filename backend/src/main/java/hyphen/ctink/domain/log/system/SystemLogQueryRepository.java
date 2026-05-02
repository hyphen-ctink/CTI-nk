package hyphen.ctink.domain.log.system;

import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.jpa.impl.JPAQueryFactory;
import hyphen.ctink.domain.log.system.dto.SystemLogSearchConditionDTO;
import hyphen.ctink.domain.log.system.entity.SystemLog;
import hyphen.ctink.domain.log.system.enums.LogStatus;
import hyphen.ctink.domain.log.system.enums.Stage;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

import static hyphen.ctink.domain.log.system.entity.QSystemLog.systemLog;

@Repository
@RequiredArgsConstructor
public class SystemLogQueryRepository {
    private final JPAQueryFactory queryFactory;

    public Page<SystemLog> search(SystemLogSearchConditionDTO cond, Pageable pageable) {
        List<SystemLog> content = queryFactory
                .selectFrom(systemLog)
                .where(
                        stageEq(cond.stage()),
                        statusEq(cond.status()),
                        createdBetween(cond.dateFrom(), cond.dateTo())
                )
                .orderBy(systemLog.createdAt.desc())
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .fetch();

        Long total = queryFactory
                .select(systemLog.count())
                .from(systemLog)
                .where(
                        stageEq(cond.stage()),
                        statusEq(cond.status()),
                        createdBetween(cond.dateFrom(), cond.dateTo())
                )
                .fetchOne();

        return new PageImpl<>(content, pageable, total != null ? total : 0);
    }

    private BooleanExpression stageEq(Stage stage) {
        return stage != null ? systemLog.stage.eq(stage) : null;
    }

    private BooleanExpression statusEq(LogStatus status) {
        return status != null ? systemLog.logStatus.eq(status) : null;
    }

    private BooleanExpression createdBetween(LocalDateTime from, LocalDateTime to) {
        if (from != null && to != null) {
            return systemLog.createdAt.between(from, to);
        } else if (from != null) {
            return systemLog.createdAt.goe(from);
        } else if (to != null) {
            return systemLog.createdAt.loe(to);
        }
        return null;
    }
}
