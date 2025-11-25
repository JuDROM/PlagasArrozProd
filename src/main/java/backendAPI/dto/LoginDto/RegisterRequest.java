package backendAPI.dto.LoginDto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegisterRequest {
    private String username;
    private String lastname;
    private String password;
    private String email;
    private String rol; // "USER", "ADMIN", "DOCENTE" (opcional)
}
