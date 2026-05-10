package hyphen.ctink.domain.admin.dto;

import java.util.List;

public record UsersResponseDTO(
        Long totalCount,
        Long totalPage,
        Long currentPage,
        List<UsersDTO> users
) {}
