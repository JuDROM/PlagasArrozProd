package backendAPI.Controller;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.http.ResponseEntity;

import backendAPI.dto.PasswordDto.ChangePasswordRequest;
import backendAPI.dto.PasswordDto.ForgotPasswordRequest;
import backendAPI.dto.PasswordDto.ResetContrasenaRequest;
import backendAPI.service.Password.PasswordService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.Map;




@RestController
@RequestMapping("/contrasena")
@RequiredArgsConstructor
public class PasswordController {
    private final PasswordService passwordService;

    @PostMapping("/olvidar")
    public ResponseEntity<String> forgotPassword(@RequestBody ForgotPasswordRequest request) {
        passwordService.forgotPassword(request);
        return ResponseEntity.ok("Correo de recuperación enviado");
    }

    @PostMapping("/reset")
    public ResponseEntity<String> resetPassword(@RequestBody ResetContrasenaRequest request) {
        passwordService.resetPassword(request);
        return ResponseEntity.ok("Contraseña actualizada correctamente");
    }

    @PostMapping("/cambiar")
    public ResponseEntity<?> changePassword(@RequestBody ChangePasswordRequest request) {
        try {
            passwordService.changePassword(request);
            return ResponseEntity.ok("Contraseña actualizada correctamente");
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}
