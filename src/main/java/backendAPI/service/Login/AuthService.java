package backendAPI.service.Login;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import backendAPI.Entity.Rol; // Importar la entidad Rol
import backendAPI.Entity.User;
import backendAPI.dto.LoginDto.RegisterRequest;
import backendAPI.repository.RolRepository; // Importar el repositorio de Rol
import backendAPI.repository.UserRepository;
import backendAPI.security.JwtService;
import backendAPI.service.Password.EmailService;
import jakarta.mail.MessagingException;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;  
    @Autowired
    private RolRepository rolRepository; // Nuevo: Repositorio para buscar roles
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private final EmailService emailService;

    // Se mantiene el constructor
    public AuthService(EmailService emailService) {
        this.emailService = emailService;
    }

    private static final int MAX_FAILED_ATTEMPTS = 2;
    private static final long LOCK_TIME_DURATION = 1;

    public Long getLock_TIME_DURATION() {
        return LOCK_TIME_DURATION;
    }

    public int getMaxFailedAttempts() {
        return MAX_FAILED_ATTEMPTS;
    }

    public User register(RegisterRequest req) {
        User user = new User();
        user.setUsername(req.getUsername());
        user.setLastname(req.getLastname());
        user.setPassword(passwordEncoder.encode(req.getPassword()));
        user.setEmail(req.getEmail());

        // Buscar el rol en la base de datos. Si no se especifica, se asigna 'AGRICULTOR'.
        String rolName = (req.getRol() != null) ? req.getRol().toUpperCase() : "AGRICULTOR";
        Rol rol = rolRepository.findByNombre(rolName)
                .orElseThrow(() -> new RuntimeException("El rol '" + rolName + "' no existe."));

        user.setRol(rol);
        userRepository.save(user);
        return user;
    }

    public String login(String username, String password) {
        User u = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        // ... (código para manejar el bloqueo de cuenta, se mantiene sin cambios) ...
        if (u.getLockTime() != null) {
            Duration duration = Duration.between(u.getLockTime(), LocalDateTime.now());
            if (duration.toMinutes() < LOCK_TIME_DURATION) {
                long remaining = LOCK_TIME_DURATION - duration.toMinutes();
                throw new RuntimeException("Cuenta bloqueada. Intenta en " + remaining + " minuto(s).");
            } else {
                u.setFailedLoginAttempts(  0);
                u.setLockTime(null);
                userRepository.save(u);
            }
        }

        // Verifica contraseña
        if (passwordEncoder.matches(password, u.getPassword())) {
            // Login exitoso
            u.setFailedLoginAttempts   (0);
            u.setLockTime(null);
            userRepository.save(u);

            // Autenticación con Spring Security
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));

            // Obtener el nombre del rol del objeto Rol y pasarlo al servicio JWT
            return jwtService.generateToken(u.getUsername(), u.getRol().getNombre());
        } else {
            // ... (código para manejar intentos fallidos, se mantiene sin cambios) ...
            int attempts = u.getFailedLoginAttempts() + 1;
            u.setFailedLoginAttempts(attempts);
            int remainingAttempts = MAX_FAILED_ATTEMPTS - attempts;

            if (attempts >= MAX_FAILED_ATTEMPTS) {
                u.setLockTime(LocalDateTime.now());
                userRepository.save(u);
                throw new RuntimeException("Contraseña incorrecta. La cuenta ha sido bloqueada por " + getLock_TIME_DURATION() + " minuto(s).");
            } else {
                userRepository.save(u);
                throw new RuntimeException("Contraseña incorrecta. Te quedan " + remainingAttempts + " intento(s).");
            }
        }
    }

    public User registerUserByAdmin(String username,String lastname, String email, String rolName) throws MessagingException {
        // Genera la contraseña temporal
        String temporaryPassword = UUID.randomUUID().toString().substring(0, 8);

        // Buscar el rol en la base de datos por su nombre
        Rol rol = rolRepository.findByNombre(rolName)
                .orElseThrow(() -> new RuntimeException("El rol '" + rolName + "' no existe."));

        // Crea y guarda el usuario
        User user = new User();
        user.setUsername(username);
        user.setLastname(lastname);
        user.setEmail(email);
        user.setRol(rol); // Asigna el objeto Rol
        user.setPassword(passwordEncoder.encode(temporaryPassword));
        userRepository.save(user);

        // Prepara el contenido HTML para el correo
        String subject = "Bienvenido a nuestra plataforma";
        String htmlBody = String.format("""
                <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eaeaea; border-radius: 10px;">
                    <h2 style="color: #1a73e8;">¡Bienvenido, %s!</h2>
                    <p>Tu cuenta de <b>%s</b> ha sido creada con éxito por un administrador.</p>
                    <p>Tu contraseña temporal es: <b>%s</b></p>
                    <p>Por favor, usa esta contraseña para iniciar sesión y cámbiala de inmediato para mantener tu cuenta segura.</p>
                    <p>Si tienes problemas, contáctanos en soporte@tuempresa.com.</p>
                </div>
                """, username, rol.getNombre().toLowerCase(), temporaryPassword);
        emailService.sendEmail(email, subject, htmlBody);
        return user;
    }
}