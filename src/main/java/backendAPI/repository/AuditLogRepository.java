package backendAPI.repository;

import backendAPI.Entity.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {
    // Para obtener los logs más recientes primero
    List<AuditLog> findAllByOrderByFechaDesc();
    List<AuditLog> findTop5ByOrderByFechaDesc();
}