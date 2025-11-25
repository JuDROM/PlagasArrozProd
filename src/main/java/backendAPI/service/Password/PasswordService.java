package backendAPI.service.Password;

import backendAPI.Entity.User;
import backendAPI.dto.PasswordDto.ChangePasswordRequest;
import backendAPI.dto.PasswordDto.ForgotPasswordRequest;
import backendAPI.dto.PasswordDto.ResetContrasenaRequest;
import backendAPI.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class PasswordService {

    private final UserRepository userRepository;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;

    private final Map<String, String> verificationCodes = new ConcurrentHashMap<>();
    private final Map<String, LocalDateTime> codeExpiries = new ConcurrentHashMap<>();

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    public void comienzoLimpiarTareas() {
        scheduler.scheduleAtFixedRate(this::limpiarCodigoExpirado, 1, 1, TimeUnit.MINUTES);
    }

    private void limpiarCodigoExpirado() {
        verificationCodes.forEach((code, email) -> {
            LocalDateTime expiryTime = codeExpiries.get(code);
            if (expiryTime != null && expiryTime.isBefore(LocalDateTime.now())) {
                verificationCodes.remove(code);
                codeExpiries.remove(code);
                log.info("🗑️ Código expirado eliminado para el usuario {}", email);
            }
        });
    }

    // ============================
    // OLVIDÓ CONTRASEÑA
    // ============================
    public void forgotPassword(ForgotPasswordRequest request) {
        log.info("📩 Solicitud de recuperación para: {}", request.getEmail());

        Optional<User> userOpt = userRepository.findByEmail(request.getEmail());
        if (userOpt.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "No se encontró un usuario con ese correo.");
        }
        User user = userOpt.get();

        String verificationCode = String.format("%06d", new Random().nextInt(999999));
        log.info("Código generado: {}", verificationCode);

        verificationCodes.put(verificationCode, user.getEmail());
        codeExpiries.put(verificationCode, LocalDateTime.now().plusMinutes(15));

        try {
            emailService.sendVerificationCodeEmail(user.getEmail(), user.getUsername(), verificationCode);
        } catch (Exception e) {
            log.error("❌ Error enviando email a {}: {}", user.getEmail(), e.getMessage(), e);
            verificationCodes.remove(verificationCode);
            codeExpiries.remove(verificationCode);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error enviando email");
        }

        log.info("✅ Código de verificación enviado para {}", user.getEmail());
    }

    // ============================
    // RESETEAR CONTRASEÑA CON CÓDIGO
    // ============================
    public void resetPassword(ResetContrasenaRequest request) {
        log.info("🔄 Reset password request: {}", request);

        String verificationCode = request.getToken();
        String userEmail = verificationCodes.get(verificationCode);
        LocalDateTime expiryTime = codeExpiries.get(verificationCode);

        verificationCodes.remove(verificationCode);
        codeExpiries.remove(verificationCode);

        if (userEmail == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Código de verificación incorrecto o no existe.");
        }
        if (expiryTime == null || expiryTime.isBefore(LocalDateTime.now())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El código ha expirado.");
        }

        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Usuario no encontrado"));

        user.setPassword(passwordEncoder.encode(request.getNuevaContrasena()));
        userRepository.save(user);

        log.info("🔑 Contraseña actualizada exitosamente para {}", user.getUsername());
    }

    // ============================
    // CAMBIAR CONTRASEÑA (USUARIO LOGUEADO)
    // ============================
    public void changePassword(ChangePasswordRequest request) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        log.info("Usuario autenticado intentando cambiar contraseña: {}", username);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado"));

        if (!passwordEncoder.matches(request.getContrasenaActual(), user.getPassword())) {
            throw new IllegalArgumentException("La contraseña actual no es correcta");
        }

        user.setPassword(passwordEncoder.encode(request.getContrasenaNueva()));
        userRepository.save(user);

        log.info("✅ Contraseña cambiada para {}", username);
    }
}