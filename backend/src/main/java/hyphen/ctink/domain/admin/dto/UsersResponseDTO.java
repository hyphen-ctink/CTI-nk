package hyphen.ctink.domain.admin.dto;

import java.util.List;

public record UsersResponseDTO(
        Long totalCount,
        Long totalPages,
        Long currentPage,
        List<UsersDTO> users
) {}
