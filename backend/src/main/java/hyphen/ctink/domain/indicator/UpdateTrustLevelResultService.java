package hyphen.ctink.domain.indicator;

import hyphen.ctink.domain.indicator.dto.UpdateTrustLevelJobResultDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UpdateTrustLevelResultService {

    private final IocRepository iocRepository;

    @Transactional
    public void process(UpdateTrustLevelJobResultDTO result) {
        if (!"success".equals(result.status())) {
            return;
        }

        var value = result.ioc();

        Ioc ioc = iocRepository.findByIocValue(value)
                .orElseThrow(() -> new RuntimeException("Ioc not found"));


        if ("misp".equals(result.platform())) {
            ioc.updateMispConfirmed(result.result());
        } else {
            ioc.updateVirustotalConfirmed(result.result());
        }
    }
}
