package backendAPI.Entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@Table(name = "audit_logs")
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String accion;
    @Column(columnDefinition = "TEXT")
    private String descripcion;
    private LocalDateTime fecha;
    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

    public AuditLog() {}
    public AuditLog(String accion, String descripcion, User user) {
        this.accion = accion;
        this.descripcion = descripcion;
        this.user = user;
        this.fecha = LocalDateTime.now();
    }
}