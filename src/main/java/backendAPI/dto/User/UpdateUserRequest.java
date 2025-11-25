package backendAPI.dto.User;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter

public class UpdateUserRequest {
    private String username;
    private String lastname;
    private String email;
    private String rol;
}
