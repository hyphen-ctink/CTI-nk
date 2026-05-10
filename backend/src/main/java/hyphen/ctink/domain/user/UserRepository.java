package hyphen.ctink.domain.user;

import hyphen.ctink.domain.user.enums.UserStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    boolean existsByLoginId(String loginId);
    boolean existsByEmail(String email);

    Optional<User> findByLoginId(String loginId);

    Page<User> findByUserStatusNot(UserStatus userStatus, Pageable pageable);

    Page<User> findByUserStatus(UserStatus userStatus, Pageable pageable);
}
