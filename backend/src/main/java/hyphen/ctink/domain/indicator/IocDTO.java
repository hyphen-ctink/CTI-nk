package hyphen.ctink.domain.indicator;

import hyphen.ctink.domain.indicator.enums.IocType;

public record IocDTO(
    IocType iocType,
    String iocValue
) {}
