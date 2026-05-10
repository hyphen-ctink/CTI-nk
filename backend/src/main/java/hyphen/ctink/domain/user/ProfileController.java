package hyphen.ctink.domain.user;

import hyphen.ctink.domain.user.dto.ProfileResponseDTO;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/ctink/profile")
public class ProfileController {

    private final ProfileService profileService;

    @GetMapping
    public ProfileResponseDTO profile(HttpSession session) {
        return profileService.profile(session);
    }
}
