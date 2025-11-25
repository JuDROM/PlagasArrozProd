package backendAPI.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;

@Service
public class JwtService {

    @Value("${app.jwt.secret:miSecretoSuperSeguroMuyLargo12345678901234567890}")
    private String SECRET;

    @Value("${app.jwt.expiration-ms:3600000}") // 1 hora por defecto
    private long EXPIRATION_MS;

    // Clave secreta
    private Key getKey() {
        return Keys.hmacShaKeyFor(SECRET.getBytes());
    }

    // ===============================
    // GENERAR TOKEN
    // ===============================
    public String generateToken(String username, String role) {
        return Jwts.builder()
                .setSubject(username) // Usuario
                .claim("role", role)  // Rol
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_MS))
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // ===============================
    // VALIDAR TOKEN
    // ===============================
    public boolean validateToken(String token) {
        try {
            extractAllClaims(token); // Si falla, lanza excepción
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    // ===============================
    // EXTRAER CLAIMS
    // ===============================
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // ===============================
    // EXTRAER USUARIO
    // ===============================
    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    // ===============================
    // EXTRAER ROL
    // ===============================
    public String extractRole(String token) {
        return extractAllClaims(token).get("role", String.class);
    }

    // ===============================
    // VERIFICAR EXPIRACIÓN
    // ===============================
    public boolean isTokenExpired(String token) {
        return extractAllClaims(token).getExpiration().before(new Date());
    }
}
