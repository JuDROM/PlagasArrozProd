package backendAPI.Controller;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional; // Import necesario para Optional

import backendAPI.Entity.AuditLog;
import backendAPI.repository.AuditLogRepository;
import backendAPI.service.LogsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder; // Para obtener el usuario autenticado
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import backendAPI.Entity.User;
import backendAPI.dto.LoginDto.AuthResponse;
import backendAPI.dto.LoginDto.RegisterRequest;
import backendAPI.dto.User.UpdateUserRequest;
import backendAPI.repository.UserRepository;
import backendAPI.security.JwtService;
import backendAPI.service.Login.AuthService;
import backendAPI.service.Login.UserService;
import backendAPI.service.Password.EmailService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.mail.MessagingException;


@RestController
@RequestMapping("/usuario")
@Tag(name = "Autenticación", description = "Endpoints para registro y login de usuarios")
public class UserController {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private AuditLogRepository auditLogRepository;
    // @Autowired private UserRepository usuarioRepository; // Eliminado por estar duplicado (ya tienes userRepository arriba)
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private AuthService authService;
    @Autowired
    private UserService userService;
    @Autowired
    private JwtService JwtService;
    @Autowired
    private LogsService LogsService;
    @Autowired
    private EmailService emailService;


    @Operation(summary = "Registrar un nuevo usuario")
    @PostMapping("/registro")
    @Transactional
    public ResponseEntity<?> registrarUsuario(@RequestBody RegisterRequest req) {

        if (req.getRol() == null || req.getRol().isBlank()) {
            req.setRol("INVESTIGADOR");
        }
        // Validar que el rol sea permitido en el registro público
        if ("ADMIN".equalsIgnoreCase(req.getRol())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body("No está permitido crear administradores desde este endpoint.");
        }

        if (!("AGRICULTOR".equalsIgnoreCase(req.getRol()) || "INVESTIGADOR".equalsIgnoreCase(req.getRol()))) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Rol inválido. Solo se permite AGRICULTOR o INVESTIGADOR en el registro público.");
        }

        if (!isValidPassword(req.getPassword())) {
            return ResponseEntity.badRequest().body("La contraseña debe tener mínimo 8 caracteres, incluir una mayúscula, " + "una minúscula, un número y un carácter especial.");
        }

        // Verificar si ya existe un usuario con ese correo
        if (req.getEmail() != null && userRepository.findByEmail(req.getEmail()).isPresent()) {
            return ResponseEntity.badRequest().body("El correo ya está registrado.");
        }

        // Crear y guardar el nuevo usuario
        User created = authService.register(req);
        return ResponseEntity.ok("Usuario registrado correctamente: " + created.getUsername());
    }

    private boolean isValidPassword(String password) {
        if (password == null) return false;
        String regex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&.#_-])[A-Za-z\\d@$!%*?&.#_-]{8,}$";
        return password.matches(regex);
    }

    @Transactional
    @Operation(summary = "Iniciar sesión y obtener token JWT")
    @PostMapping("/inicio-sesion")
    public ResponseEntity<?> login(@RequestBody User user) {
        try {
            User dbUser = userRepository.findByUsername(user.getUsername())
                    .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

            // Verifica si la cuenta está bloqueada
            if (dbUser.getLockTime() != null) {
                long minutesLocked = java.time.temporal.ChronoUnit.MINUTES.between(dbUser.getLockTime(), LocalDateTime.now());
                if (minutesLocked < authService.getLock_TIME_DURATION()) {
                    return ResponseEntity.status(403)
                            .body(Map.of("error", "Cuenta bloqueada. Intenta más tarde."));
                } else {
                    dbUser.setFailedLoginAttempts(0);
                    dbUser.setLockTime(null);
                    userRepository.save(dbUser);
                }
            }

            if (passwordEncoder.matches(user.getPassword(), dbUser.getPassword())) {
                dbUser.setFailedLoginAttempts(0);
                dbUser.setLockTime(null);
                userRepository.save(dbUser);

                authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword())
                );

                String token = JwtService.generateToken(dbUser.getUsername(), dbUser.getRol().getNombre());
                return ResponseEntity.ok(new AuthResponse(token, dbUser.getRol().getNombre()));

            } else {
                int attempts = dbUser.getFailedLoginAttempts() + 1;
                dbUser.setFailedLoginAttempts(attempts);

                if (attempts >= authService.getMaxFailedAttempts()) {
                    dbUser.setLockTime(LocalDateTime.now());
                    userRepository.save(dbUser);
                    return ResponseEntity.status(403)
                            .body(Map.of("error", "Contraseña incorrecta. La cuenta ha sido bloqueada por " + authService.getLock_TIME_DURATION() + " minuto(s)."));
                } else {
                    userRepository.save(dbUser);
                    int remaining = authService.getMaxFailedAttempts() - attempts;
                    return ResponseEntity.status(401)
                            .body(Map.of("error", "Contraseña incorrecta. Te quedan " + remaining + " intento(s)."));
                }
            }

        } catch (org.springframework.security.authentication.DisabledException ex) {
            return ResponseEntity.status(403).body(Map.of("error", "El usuario está desactivado"));
        } catch (Exception ex) {
            return ResponseEntity.status(500).body(Map.of("error", "Error en autenticación: " + ex.getMessage()));
        }
    }

    @Transactional
    @Operation(summary = "Cambiar el estado (habilitar/deshabilitar) de un usuario")
    @PutMapping("/admin/{id}/estado")
    public ResponseEntity<String> cambiarEstado(
            @PathVariable Long id,
            @RequestBody Map<String, Boolean> body) {

        boolean enabled = body.get("enabled");
        userService.toggleEnable(id, enabled);

        String estado = enabled ? "activado" : "desactivado";

        String currentUsername = SecurityContextHolder.getContext().getAuthentication().getName();
        Optional<User> adminOpt = userRepository.findByUsername(currentUsername);

        if (adminOpt.isPresent()) {
            AuditLog log = new AuditLog(
                    enabled ? "ACTIVACION_USUARIO" : "DESACTIVACION_USUARIO",
                    "El estado del usuario ID " + id + " cambió a " + (enabled ? "Activo" : "Inactivo"),
                    adminOpt.get() // Pasamos el objeto User (Admin)
            );
            auditLogRepository.save(log);
        }

        return ResponseEntity.ok("Usuario " + estado + " correctamente");
    }

    @Transactional
    @Operation(summary = "Registrar un nuevo usuario por el administrador")
    @PostMapping("/admin/registro")
    public ResponseEntity<?> registerByAdmin(@RequestBody RegisterRequest req) {
        if (req.getEmail() == null || userRepository.findByEmail(req.getEmail()).isPresent()) {
            return ResponseEntity.badRequest().body("Email ya registrado o inválido.");
        }
        try {
            User createdUser = authService.registerUserByAdmin(req.getUsername(), req.getLastname(), req.getEmail(), req.getRol());
            return ResponseEntity.ok("Usuario " + createdUser.getUsername() + " registrado. Contraseña y rol asignado enviados al correo.");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body("Error al crear usuario: " + e.getMessage());
        } catch (MessagingException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al crear usuario: No se pudo enviar el correo de bienvenida.");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al crear usuario: " + e.getMessage());
        }
    }

    @Transactional
    @Operation(summary = "Cambiar los datos de un usuario existente")
    @PutMapping("/admin/{id}")
    public ResponseEntity<User> actualizarUsuario(
            @PathVariable Long id,
            @RequestBody UpdateUserRequest request) {

        User actualizado = userService.updateUser(id, request);
        return ResponseEntity.ok(actualizado);
    }

    @Transactional
    @Operation(summary = "Crear un nuevo administrador (solo accesible por ADMIN)")
    @PreAuthorize("hasRole('ADMINISTRADOR')")
    @PostMapping("/admin/crear")
    public ResponseEntity<?> crearAdministrador(@RequestBody RegisterRequest req) {

        req.setRol("ADMINISTRADOR");

        if (!isValidPassword(req.getPassword())) {
            return ResponseEntity.badRequest().body(
                    "La contraseña debe tener mínimo 8 caracteres, incluir una mayúscula, " +
                    "una minúscula, un número y un carácter especial."
            );
        }

        if (req.getEmail() != null && userRepository.findByEmail(req.getEmail()).isPresent()) {
            return ResponseEntity.badRequest().body("El correo ya está registrado.");
        }

        User created = authService.register(req);
        return ResponseEntity.ok("Administrador creado correctamente: " + created.getUsername());
    }


    @Operation(summary = "Obtener todos los usuarios excepto el logueado")
    @PreAuthorize("hasRole('ADMINISTRADOR')")
    @GetMapping("/admin/listar/{loggedUserId}")
    public ResponseEntity<List<User>> listarUsuarios(@PathVariable Long loggedUserId) {
        List<User> usuarios = userService.getAllUsersExcept(loggedUserId);
        return ResponseEntity.ok(usuarios);
    }

    @Transactional
    @Operation(summary = "Eliminar un usuario (con confirmación y validaciones de rol)")
    @PreAuthorize("hasRole('ADMINISTRADOR')")
    @DeleteMapping("/admin/eliminar/{userId}/{loggedUserId}")
    public ResponseEntity<?> eliminarUsuario(
            @PathVariable Long userId,
            @PathVariable Long loggedUserId,
            @RequestBody(required = false) Map<String, Boolean> confirmacion) {

        if (confirmacion == null || !confirmacion.getOrDefault("confirmar", false)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("¿Estás seguro que deseas eliminar este usuario? Debes enviar {\"confirmar\": true} en el body.");
        }

        try {
            // --- PASO 1: Obtener datos del usuario a eliminar para el log ---
            String nombreUsuario = "ID " + userId;
            Optional<User> usuarioEliminadoOpt = userRepository.findById(userId);
            if (usuarioEliminadoOpt.isPresent()) {
                nombreUsuario = usuarioEliminadoOpt.get().getUsername();
            }

            // --- PASO 2: Obtener al ADMIN (Manejo de Optional) ---
            User adminUser = null;
            Optional<User> adminOpt = userRepository.findById(loggedUserId);

            if (adminOpt.isPresent()) {
                adminUser = adminOpt.get();
            } else {
                // Logueamos error en consola si el admin no se encuentra (caso raro)
                System.err.println("Advertencia: Admin con ID " + loggedUserId + " no encontrado al intentar loguear la acción.");
            }

            // --- PASO 3: Ejecutar el borrado real ---
            userService.deleteUser(userId, loggedUserId);

            // --- PASO 4: Guardar el Log solo si tenemos al admin ---
            if (adminUser != null) {
                AuditLog log = new AuditLog(
                        "ELIMINACION_USUARIO",
                        "Se eliminó al usuario '" + nombreUsuario + "'",
                        adminUser // CORRECCIÓN: Pasamos el objeto User completo
                );
                auditLogRepository.save(log);
            }

            return ResponseEntity.ok("Usuario eliminado correctamente.");

        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Error: " + e.getMessage());
        }
    }


    @Operation(summary = "Obtener todos los logs de la DB")
    @PreAuthorize("hasRole('ADMINISTRADOR')")
    @GetMapping("/admin/logs")
    public ResponseEntity<List<AuditLog>> getAllLogs() {
        return ResponseEntity.ok(LogsService.getAllLogs());
    }

    @Operation(summary = "Obtener los primeros 5 logs ")
    @PreAuthorize("hasRole('ADMINISTRADOR')")
    @GetMapping("/admin/fiveLogs")
    public ResponseEntity<List<AuditLog>> getFirstFiveLogs() {
        return ResponseEntity.ok(LogsService.getFirstFiveLogs());
    }
}