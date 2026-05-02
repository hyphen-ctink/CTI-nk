package hyphen.ctink.domain.log.notification.enums;

import lombok.Getter;

@Getter
public enum Decision {
    APPROVED("승인이 완료되었습니다."),
    REJECTED("거부가 완료되었습니다.");

    private final String message;

    Decision(String message) {
        this.message = message;
    }
}
