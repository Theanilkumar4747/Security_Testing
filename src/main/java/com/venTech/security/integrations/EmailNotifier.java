package com.venTech.security.integrations;

import com.venTech.security.gate.QualityGate;
import com.venTech.security.model.ScanReport;
import com.venTech.security.utils.EnvConfig;
import jakarta.mail.Authenticator;
import jakarta.mail.Message;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import java.nio.file.Path;
import java.util.Properties;

/** SMTP notifier. Settings: smtp.host, smtp.port, smtp.user, smtp.password (env), email.from, email.to (comma list). */
public class EmailNotifier {
    private final Session session;
    private final String from;
    private final String to;

    private EmailNotifier(Session session, String from, String to) { this.session = session; this.from = from; this.to = to; }

    public static EmailNotifier fromEnv() {
        Properties p = new Properties();
        p.put("mail.smtp.host", EnvConfig.require("smtp.host"));
        p.put("mail.smtp.port", EnvConfig.get("smtp.port", "587"));
        p.put("mail.smtp.starttls.enable", "true");
        String user = EnvConfig.get("smtp.user", "");
        String pass = EnvConfig.get("smtp.password", "");
        Session s;
        if (user.isBlank()) {
            s = Session.getInstance(p);
        } else {
            p.put("mail.smtp.auth", "true");
            s = Session.getInstance(p, new Authenticator() {
                @Override protected PasswordAuthentication getPasswordAuthentication() { return new PasswordAuthentication(user, pass); }
            });
        }
        return new EmailNotifier(s, EnvConfig.require("email.from"), EnvConfig.require("email.to"));
    }

    public void notifyScan(ScanReport report, QualityGate.GateResult gate, Path htmlReport) throws Exception {
        MimeMessage m = new MimeMessage(session);
        m.setFrom(new InternetAddress(from));
        m.setRecipients(Message.RecipientType.TO, InternetAddress.parse(to));
        m.setSubject("[Security] " + (gate.passed() ? "PASSED" : "FAILED") + " - " + report.target().name());

        StringBuilder body = new StringBuilder("Findings by severity: " + report.countBySeverity() + "\n");
        gate.violations().forEach(v -> body.append("\n- ").append(v));

        MimeMultipart mp = new MimeMultipart();
        MimeBodyPart text = new MimeBodyPart();
        text.setText(body.toString());
        mp.addBodyPart(text);
        if (htmlReport != null) {
            MimeBodyPart att = new MimeBodyPart();
            att.attachFile(htmlReport.toFile());
            mp.addBodyPart(att);
        }
        m.setContent(mp);
        Transport.send(m);
    }
}
