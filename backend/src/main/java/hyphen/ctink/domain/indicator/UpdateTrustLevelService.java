package hyphen.ctink.domain.indicator;

import hyphen.ctink.domain.cti.enums.CtiPlatform;
import hyphen.ctink.domain.indicator.enums.TrustLevel;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
@RequiredArgsConstructor
public class UpdateTrustLevelService {

    private final IocRepository iocRepository;

    public void updateTrustLevel(Long iocId) {
        Ioc ioc = iocRepository.findById(iocId)
                .orElseThrow(() -> new RuntimeException("Ioc not found"));

        Set<CtiPlatform> platforms = ioc.getPlatformName();

        int platformCount = (platforms == null) ? 0 : platforms.size();

        if (platformCount < 3) {
            if (ioc.isMispConfirmed() && ioc.isVirustotalConfirmed()) {
                ioc.setTrustLevel(TrustLevel.HIGH);
            } else if (ioc.isMispConfirmed() || ioc.isVirustotalConfirmed()) {
                ioc.setTrustLevel(TrustLevel.MEDIUM);
            } else {
                ioc.setTrustLevel(TrustLevel.LOW);
            }
        } else {
            if (ioc.isMispConfirmed() || ioc.isVirustotalConfirmed()) {
                ioc.setTrustLevel(TrustLevel.HIGH);
            } else {
                ioc.setTrustLevel(TrustLevel.MEDIUM);
            }
        }

    }
}
