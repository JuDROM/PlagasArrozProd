package backendAPI.Entity;


import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import lombok.*;

import jakarta.persistence.*;

@Setter
@Getter
@Entity
@Table(name = "users") // Nombre de la tabla en la base de datos
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long  id;

    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private String lastname;

    @Column(nullable = false , unique = false)
    private String password;

    @Column(unique = true , nullable = false)
    private String email;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "rol_id", nullable = false)
    private Rol rol;

    private boolean enabled = true;

    
    private int failedLoginAttempts = 0;
    private LocalDateTime lockTime;

    // Constructor vacío requerido por JPA
    public User() {}

    // Constructor de conveniencia
    public User(String username,String lastname, String password, String email) {
        this.username = username;
        this.lastname = lastname;
        this.password = password;
        this.email = email;
        this.enabled = true;
    }

    // Getters y Setters

    public boolean isAccountLocked() {
        if (lockTime == null) return false;
        long minutesLocked = ChronoUnit.MINUTES.between(lockTime, LocalDateTime.now());
        return minutesLocked < 15; // 15 minutos de bloqueo
    }
    public void incrementFailedLoginAttempts() {
        this.failedLoginAttempts++;
        if (this.failedLoginAttempts >= 5) {
            this.lockTime = LocalDateTime.now();
        }
    }

    
}
