package backendAPI.repository;

import backendAPI.Entity.Rol;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface RolRepository extends JpaRepository<Rol, Long> {
    
    /**
     * Busca un rol en la base de datos por su nombre.
     * @param nombre El nombre del rol (ej. "ADMINISTRADOR").
     * @return Un objeto Optional que contiene el Rol si se encuentra, o un Optional vacío.
     */
    Optional<Rol> findByNombre(String nombre);
}
