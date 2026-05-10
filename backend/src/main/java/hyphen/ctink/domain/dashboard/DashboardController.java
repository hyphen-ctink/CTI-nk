package hyphen.ctink.domain.dashboard;

import hyphen.ctink.domain.dashboard.dto.DashboardResponseDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/ctink/overview")
public class DashboardController {
    private final DashboardService dashboardService;

    @GetMapping
    public DashboardResponseDTO getDashboard() {
        return dashboardService.getDashboard();
    }
}
