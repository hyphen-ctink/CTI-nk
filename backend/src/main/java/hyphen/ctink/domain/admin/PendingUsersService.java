package hyphen.ctink.domain.admin;

import hyphen.ctink.domain.user.User;
import hyphen.ctink.domain.user.UserRepository;
import hyphen.ctink.domain.admin.dto.PendingUsersDTO;
import hyphen.ctink.domain.admin.dto.PendingUsersResponseDTO;
import hyphen.ctink.domain.user.enums.UserStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PendingUsersService {

    private final UserRepository userRepository;

    public PendingUsersResponseDTO getPendingUsers(Integer reqPage) {
        int page = (reqPage == null ? 1 : reqPage);

        Pageable pageable = PageRequest.of(
                page - 1,
                3
        );

        Page<User> queryResult = userRepository.findByUserStatus(
                UserStatus.PENDING, pageable
        );
        Page<PendingUsersDTO> result = queryResult.map(user ->
                new PendingUsersDTO(
                        user.getLoginId(),
                        user.getName(),
                        user.getOrganization(),
                        user.getPosition(),
                        user.getEmail(),
                        user.getPhone(),
                        user.getCreatedAt()
                )
        );

        return new PendingUsersResponseDTO(
                result.getTotalElements(),
                (long) result.getTotalPages(),
                (long) result.getNumber() + 1,
                result.getContent()
        );
    }
}
