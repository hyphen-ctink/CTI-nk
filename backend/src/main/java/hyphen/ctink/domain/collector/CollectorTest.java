package hyphen.ctink.domain.collector;

import hyphen.ctink.domain.collector.dto.CollectorResultDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/ctink/test")
public class CollectorTest {

    private final CollectorSchedularService service;
    private final CollectorResultService resultService;

    @GetMapping
    public String runTest() {
        System.out.println(LocalDateTime.now());
        service.runCollection();
        return "ok";
    }

    @PostMapping("/result")
    public String saveTest(@RequestBody CollectorResultDTO results) {
        resultService.process(results);
        System.out.println(LocalDateTime.now());
        return "Finish";
    }
}
