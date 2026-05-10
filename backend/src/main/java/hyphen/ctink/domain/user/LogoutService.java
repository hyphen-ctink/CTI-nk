package hyphen.ctink.domain.user;

import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutService {

    public void logout(HttpSession session) {
        if(session != null) {
            session.invalidate();
        }
    }
}
