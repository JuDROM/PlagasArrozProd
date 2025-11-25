package backendAPI.service.Password;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;


@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;

    public void sendVerificationCodeEmail(String to, String nombreUsuario, String verificationCode) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
        System.out.println("Enviando email de " + to);
        helper.setTo(to);
        helper.setSubject("Código de Verificación para Restablecer Contraseña");

        String htmlContent = """
                <div style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eaeaea; border-radius: 10px;">
                    <p style="font-size: 16px;">Hola <b>%s</b>,</p>
                    
                    <p style="font-size: 14px;">
                        Has solicitado restablecer tu contraseña. Usa el siguiente código para verificar tu identidad:
                    </p>

                    <h2 style="text-align: center; color: #1a73e8; font-size: 24px; letter-spacing: 5px;">
                        %s
                    </h2>

                    <p style="font-size: 14px;">
                        Este código es válido por 15 minutos. Si no solicitaste este cambio, ignora este correo.
                    </p>

                    <p style="font-size: 12px; color: #555;">
                        Si tienes alguna duda adicional, contáctanos en 
                        <a href="mailto:soporte@miapp.com" style="color: #1a73e8;">soporte@miapp.com</a>
                    </p>

                    <p style="margin-top: 20px;">Saludos cordiales,</p>
                    <p><b>Equipo MiApp</b></p>
                </div>
                """.formatted(nombreUsuario, verificationCode);

        helper.setText(htmlContent, true); // true => HTML
        mailSender.send(message);
    }


    // Método original, mantenido por si es necesario en otro contexto
    public void sendEmail(String to, String subject, String text) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(text, true); // true indica que el contenido es HTML

        mailSender.send(message);
    }
}