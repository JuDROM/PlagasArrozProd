
FROM maven:3.9-eclipse-temurin-21 AS backend-builder 

WORKDIR /app

# Copiar todo el repositorio. 
COPY . .

# Compilar el proyecto Maven.
RUN mvn clean install -DskipTests

# ---------------------------------------------------------------------
# FASE 2: IMAGEN FINAL DE PRODUCCIÓN (Ejecución con JRE 21)
# Se usa una imagen ligera de Java 21 Runtime Environment (JRE).
# ---------------------------------------------------------------------
FROM eclipse-temurin:21-jre-alpine 
# 🚨 CORRECCIÓN: Se cambió temurin:17-jre-alpine a temurin:21-jre-alpine

WORKDIR /app

# Copiar el JAR compilado de la Fase 1 (el nombre del JAR es genérico para funcionar con cualquier nombre)
COPY --from=backend-builder /app/target/*.jar app.jar

# Exponer el puerto de Spring Boot
EXPOSE 8080

# Comando de inicio
ENTRYPOINT ["java", "-jar", "app.jar"]