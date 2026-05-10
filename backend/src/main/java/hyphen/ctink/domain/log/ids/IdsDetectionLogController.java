package hyphen.ctink.domain.log.ids;

import hyphen.ctink.domain.log.ids.dto.IdsDetectionLogRequestDTO;
import hyphen.ctink.domain.log.ids.dto.IdsDetectionLogResponseDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/ctink/logs/ids")
public class IdsDetectionLogController {
    private final IdsDetectionLogService idsDetectionLogService;

    @GetMapping
    public IdsDetectionLogResponseDTO getIdsDetectionLogs(IdsDetectionLogRequestDTO req) {
        return idsDetectionLogService.getIdsDetectionLog(req);
    }
}
