package backendAPI.dto.PasswordDto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class ResetContrasenaRequest {
    @NotBlank
    private String token;
   
    @NotBlank
    private String nuevaContrasena;
}
