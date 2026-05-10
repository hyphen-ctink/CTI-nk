package hyphen.ctink.domain.collector;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/test")
public class CollectorTest {
    private final CollectorService collectorService;

    @GetMapping("/send")
    public String send() {
        collectorService.testSend();
        return "ok";
    }
}
