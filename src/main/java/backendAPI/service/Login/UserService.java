package backendAPI.service.Login;

import backendAPI.Entity.Rol;
import backendAPI.Entity.User;
import backendAPI.dto.User.UpdateUserRequest;
import backendAPI.repository.RolRepository;
import backendAPI.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RolRepository rolRepository;

    public User save(User user) {
        return userRepository.save(user);
    }

    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public User toggleEnable(Long id, boolean estado) {
        User usuario = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        usuario.setEnabled(estado);
        return userRepository.save(usuario);
    }
    public User updateUser(Long id, UpdateUserRequest request) {
        User usuario = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        if (request.getUsername() != null) {
            usuario.setUsername(request.getUsername());
        }
        if (request.getLastname() != null) {
            usuario.setLastname(request.getLastname());
        }
        if (request.getEmail() != null) {
            usuario.setEmail(request.getEmail());
        }
        if (request.getRol() != null) {
            Rol rol = rolRepository.findByNombre(request.getRol())
                    .orElseThrow(() -> new RuntimeException("Rol no encontrado"));
            usuario.setRol(rol);
        }

        return userRepository.save(usuario);
    }

    public List<User> getAllUsersExcept(Long loggedUserId) {
        return userRepository.findAllExcept(loggedUserId);
    }

    // 🔹 Eliminar usuario con validación especial para ADMIN
    public void deleteUser(Long userId, Long loggedUserId) {
        User usuario = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        if (usuario.getId() == loggedUserId) {
            throw new RuntimeException("No puedes eliminar tu propio usuario.");
        }

        if ("ADMIN".equalsIgnoreCase(usuario.getRol().getNombre())) {
            long countAdmins = userRepository.countByRole("ADMIN");
            if (countAdmins <= 1) {
                throw new RuntimeException("No se puede eliminar el último ADMIN del sistema.");
            }
        }

        userRepository.delete(usuario);
    }
}
