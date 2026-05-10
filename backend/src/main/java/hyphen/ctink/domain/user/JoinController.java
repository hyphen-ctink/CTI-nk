package hyphen.ctink.domain.user;

import hyphen.ctink.domain.user.dto.JoinRequestDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/ctink/auth/join")
public class JoinController {

    private final JoinService joinService;

    @PostMapping
    public String join(@RequestBody JoinRequestDTO req) {
        return joinService.joinUser(req);
    }
}
