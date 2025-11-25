package backendAPI.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.util.List;
import backendAPI.Entity.User;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    Optional<User> findById(Long id);

    // Todos menos el logueado
    @Query("SELECT u FROM User u WHERE u.id <> :excludeId")
    List<User> findAllExcept(@Param("excludeId") Long excludeId);

    // Contar cuántos usuarios tienen un rol específico
    @Query("SELECT COUNT(u) FROM User u WHERE u.rol.nombre = :roleName")
    long countByRole(@Param("roleName") String roleName);
}