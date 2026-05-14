package hyphen.ctink.domain.indicator;

import hyphen.ctink.domain.indicator.dto.SearchIocJobDTO;
import hyphen.ctink.mq.producer.SearchIocProducer;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class SearchIocService {

    private final SearchIocProducer producer;
    private final IocRepository iocRepository;

    @Transactional
    public void searchIoc() {

        List<Ioc> iocs = iocRepository.findByMispConfirmedFalseOrVirustotalConfirmedFalse();

        for (Ioc ioc : iocs) {
            if (!ioc.isMispConfirmed()) {
                SearchIocJobDTO message = new SearchIocJobDTO(
                        ioc.getIocValue(),
                        "misp"
                );

                producer.send(message);
            }

            if (!ioc.isVirustotalConfirmed()) {
                SearchIocJobDTO message = new SearchIocJobDTO(
                        ioc.getIocValue(),
                        "virustotal"
                );

                producer.send(message);
            }
        }

    }
}
