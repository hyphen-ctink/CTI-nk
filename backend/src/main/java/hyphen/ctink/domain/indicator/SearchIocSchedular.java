package hyphen.ctink.domain.indicator;

import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@EnableScheduling
public class SearchIocSchedular {

    private final SearchIocService updateTrustLevelService;

    @Scheduled(cron = "0 0 3 * * MON")
    public void run() {
        updateTrustLevelService.searchIoc();
    }
}
