package hyphen.ctink.domain.dashboard;

import hyphen.ctink.domain.dashboard.dto.DetectionReportDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/ctink/logs/ids/report")
public class DetectionReportController {

    private final DetectionReportService detectionReportService;

    @GetMapping
    public DetectionReportDTO getDetectionReport() {
        return detectionReportService.getDetectionReport();
    }

}
