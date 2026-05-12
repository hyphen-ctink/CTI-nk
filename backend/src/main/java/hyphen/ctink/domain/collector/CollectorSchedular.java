package hyphen.ctink.domain.collector;

import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@EnableScheduling
public class CollectorSchedular {

    private final CollectorSchedularService schedularService;

    @Scheduled(cron = "0 0 * * * *")
    public void run() {
        schedularService.runCollection();
    }
}
