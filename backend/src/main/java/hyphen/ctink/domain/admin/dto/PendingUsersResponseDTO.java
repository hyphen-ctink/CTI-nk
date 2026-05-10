package hyphen.ctink.domain.admin.dto;

import java.util.List;

public record PendingUsersResponseDTO(
        Long totalCount,
        Long totalPage,
        Long currentPage,
        List<PendingUsersDTO> users
) {}
