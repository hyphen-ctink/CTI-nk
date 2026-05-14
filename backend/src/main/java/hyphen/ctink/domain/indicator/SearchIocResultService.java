package hyphen.ctink.domain.indicator;

import hyphen.ctink.domain.indicator.dto.SearchIocJobResultDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class SearchIocResultService {

    private final IocRepository iocRepository;
    private final UpdateTrustLevelService updateTrustLevelService;

    @Transactional
    public void process(SearchIocJobResultDTO result) {
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

        updateTrustLevelService.updateTrustLevel(ioc.getId());
    }
}
