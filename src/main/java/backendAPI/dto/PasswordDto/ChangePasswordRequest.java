package backendAPI.dto.PasswordDto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.AllArgsConstructor;
@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ChangePasswordRequest {
    private String contrasenaActual;
    private String contrasenaNueva;
}
