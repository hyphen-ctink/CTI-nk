package hyphen.ctink.domain.log.system;

import hyphen.ctink.domain.log.system.dto.SystemLogRequestDTO;
import hyphen.ctink.domain.log.system.dto.SystemLogResponseDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/ctink/logs/system")
public class SystemLogController {
    private final SystemLogService systemLogService;

    @GetMapping
    public SystemLogResponseDTO getSystemLogs(SystemLogRequestDTO req) {
        return systemLogService.getSystemLog(req);
    }
}
