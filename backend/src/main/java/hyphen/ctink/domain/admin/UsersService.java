package hyphen.ctink.domain.admin;

import hyphen.ctink.domain.user.User;
import hyphen.ctink.domain.user.UserRepository;
import hyphen.ctink.domain.admin.dto.UsersDTO;
import hyphen.ctink.domain.admin.dto.UsersResponseDTO;
import hyphen.ctink.domain.user.enums.UserStatus;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UsersService {

    private final UserRepository userRepository;

    public UsersResponseDTO getUsers(Integer reqPage) {
        int page = (reqPage == null ? 1 : reqPage);

        Pageable pageable = PageRequest.of(
                page - 1,
                5
        );

        Page<User> queryResult = userRepository.findByUserStatusNot(
                UserStatus.PENDING, pageable
        );
        Page<UsersDTO> result = queryResult.map(user ->
                new UsersDTO(
                        user.getLoginId(),
                        user.getName(),
                        user.getOrganization(),
                        user.getPosition(),
                        user.getEmail(),
                        user.getPhone(),
                        user.getRole(),
                        user.getUserStatus(),
                        user.getLastLoginAt()
                )
        );

        return new UsersResponseDTO(
                result.getTotalElements(),
                (long) result.getTotalPages(),
                (long) result.getNumber() + 1,
                result.getContent()
        );
    }
}
