package hyphen.ctink.domain.indicator;

import hyphen.ctink.domain.indicator.dto.UpdateTrustLevelJobDTO;
import hyphen.ctink.mq.producer.UpdateTrustLevelProducer;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UpdateTrustLevelService {

    private final UpdateTrustLevelProducer producer;
    private final IocRepository iocRepository;

    @Transactional
    public void updateTrustLevel() {

        List<Ioc> iocs = iocRepository.findByMispConfirmedFalseOrVirustotalConfirmedFalse();

        for (Ioc ioc : iocs) {
            if (!ioc.isMispConfirmed()) {
                UpdateTrustLevelJobDTO message = new UpdateTrustLevelJobDTO(
                        ioc.getIocValue(),
                        "misp"
                );

                producer.send(message);
            }

            if (!ioc.isVirustotalConfirmed()) {
                UpdateTrustLevelJobDTO message = new UpdateTrustLevelJobDTO(
                        ioc.getIocValue(),
                        "virustotal"
                );

                producer.send(message);
            }
        }

    }
}
