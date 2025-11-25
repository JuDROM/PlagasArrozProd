INSERT INTO rol (nombre) VALUES ('ADMINISTRADOR') ON CONFLICT (nombre) DO NOTHING;
INSERT INTO rol (nombre) VALUES ('AGRICULTOR') ON CONFLICT (nombre) DO NOTHING;
INSERT INTO rol (nombre) VALUES ('INVESTIGADOR') ON CONFLICT (nombre) DO NOTHING;

INSERT INTO users (username, apellido, email, password, rol_id, enabled , failed_login_attempts)
VALUES ('admin', 'super', 'admin@system.com', '$2a$12$PTXUnCffd9vs34FiIlscPOsrWmhnmtpRKnR.2dtP80oGa6p9P8VVq', 1, true,0);/* password is 'administrador123.' */