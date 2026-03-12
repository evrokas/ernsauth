<?php

class Mailer
{
    public static function sendOtp(Config $config, string $email, string $code): bool
    {
        $subject = 'Your ErnsAuth verification code';
        $body = "Your verification code is: <strong>{$code}</strong><br><br>Valid for 10 minutes. Do not share this code.";
        return self::send($config, $email, $subject, $body);
    }

    public static function sendPasswordReset(Config $config, string $email, string $code): bool
    {
        $subject = 'ErnsAuth password reset';
        $body = "Your password reset code is: <strong>{$code}</strong><br><br>Valid for 30 minutes. If you did not request this, ignore this email.";
        return self::send($config, $email, $subject, $body);
    }

    private static function send(Config $config, string $to, string $subject, string $htmlBody): bool
    {
        $smtpHost = $config->get('smtp_host', '');
        if (empty($smtpHost)) {
            error_log("ErnsAuth Mailer: SMTP not configured");
            return false;
        }

        $libDir = dirname(__DIR__) . '/lib/phpmailer/src/';
        if (!file_exists($libDir . 'PHPMailer.php')) {
            error_log("ErnsAuth Mailer: PHPMailer library not found at {$libDir}");
            return false;
        }

        require_once $libDir . 'Exception.php';
        require_once $libDir . 'PHPMailer.php';
        require_once $libDir . 'SMTP.php';

        $mail = new PHPMailer\PHPMailer\PHPMailer(true);

        try {
            $mail->isSMTP();
            $mail->Host       = $smtpHost;
            $mail->SMTPAuth   = true;
            $mail->Username   = $config->get('smtp_user', '');
            $mail->Password   = $config->get('smtp_pass', '');
            $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
            $mail->Port       = $config->get('smtp_port', 587);

            $mail->setFrom(
                $config->get('smtp_from', 'noreply@example.com'),
                $config->get('smtp_from_name', 'ErnsAuth')
            );
            $mail->addAddress($to);
            $mail->isHTML(true);
            $mail->Subject = $subject;
            $mail->Body    = $htmlBody;
            $mail->AltBody = strip_tags(str_replace('<br>', "\n", $htmlBody));

            $mail->send();
            return true;
        } catch (Exception $e) {
            error_log("ErnsAuth Mailer error: " . $e->getMessage());
            return false;
        }
    }
}
