package hyphen.ctink.domain.admin;

import hyphen.ctink.domain.admin.dto.*;
import hyphen.ctink.domain.log.notification.enums.Decision;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/ctink/admin/users")
public class UsersController {
    private final UsersService usersService;
    private final PendingUsersService pendingUsersService;
    private final JoinDecisionService joinDecisionService;
    private final UserUpdateService userUpdateService;

    @GetMapping
    public UsersResponseDTO getUsers(
            @RequestParam(required = false) Integer page
    ) {
        return usersService.getUsers(page);
    }

    @GetMapping("/pending")
    public PendingUsersResponseDTO getPendingUsers(
            @RequestParam(required = false) Integer page
    ) {
        return pendingUsersService.getPendingUsers(page);
    }

    @PatchMapping("/{userId}/decision")
    public DecisionResponseDTO decideUser(
            @PathVariable Long userId,
            @RequestBody DecisionRequestDTO req
            ) {
        Decision decision = joinDecisionService.decideJoin(userId, req);
        return new DecisionResponseDTO(decision.getMessage());
    }

    @PatchMapping("/{userId}")
    public String updateUser(
            @PathVariable Long userId,
            @RequestBody UserUpdateRequestDTO req
    ) {
        return userUpdateService.userUpdate(req, userId);
    }
}
