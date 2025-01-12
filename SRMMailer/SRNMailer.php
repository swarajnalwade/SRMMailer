<?php

/*
 * SRMMailer - A custom SMTP mailer script
 * Copyright (c) 2025 Your Swaraj Nalwade
 * Licensed under the MIT License (https://opensource.org/licenses/MIT)
 */

class SRNMailer
{
    /*
       Notes for using SRNMailer:
        1.Use SSL instead of TLS because TLS might be blocked on your server and cause issues.
        2.Use your domain email, as services like Gmail, Yahoo, and Zoho might be blocked on your server.
        3.Add this line at the top of your validation file: 
             require_once __DIR__ . '/SRMMailer/SRNMailer.php';
        4.Make sure "SRNMailer.php" is in the "SRMMailer" folder.
        5. Always sanitize input fileds in you validation file.
           Example:  1. $email = filter_var(trim($_POST['email']), FILTER_SANITIZE_EMAIL);
                     2. $name = filter_var(trim($_POST['name']), FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        6.Use customMail() instead of PHP's mail() function when sending emails.
        7.Everything else stays the same. Just replace mail() with customMail().
    */
   
    private $host = 'smtp.example.com';     // SMTP server
    private $port = 465;                    // SMTP port (for SSL)
    private $encryption = 'ssl';            // Encryption type (ssl or tls)
    private $username = 'your_email@example.com'; // SMTP username
    private $password = 'your_password';            // SMTP password
    private $fromEmail = 'noreply@example.com';     // Default sender email
    private $fromName = 'My Application';      // Default sender name


    // Function to sanitize input DATA
    public function sanitizeInput($data, $type = 'string')
    {
        // Apply appropriate sanitization based on the type
        switch ($type) {
            case 'email':
                return filter_var(trim($data), FILTER_SANITIZE_EMAIL);
            case 'string':
                return filter_var(trim($data), FILTER_SANITIZE_FULL_SPECIAL_CHARS);
            case 'int':
                return filter_var(trim($data), FILTER_SANITIZE_NUMBER_INT);
            default:
                return filter_var(trim($data), FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        }
    }

    public function sendMail($to, $subject, $message, $headers)
    {
        // Sanitize input data before proceeding
        $to = $this->sanitizeInput($to, 'email');
        $subject = $this->sanitizeInput($subject);
        $message = $this->sanitizeInput($message);

        // Clean the headers to avoid duplicate `From` entries
        $headers = $this->sanitizeInput($headers);
        $headersArray = explode("\r\n", $headers);
        $headersArray = array_filter($headersArray, function ($header) {
            return stripos($header, 'From:') !== 0; // Remove any `From:` header
        });
        $headers = implode("\r\n", $headersArray);

        // Determine encryption type and set appropriate port
        if ($this->encryption == 'tls') {
            $this->port = 587; // TLS uses port 587
        }

        // SMTP connection
        $contextOptions = [
            'ssl' => [
                'allow_self_signed' => true,
                'verify_peer' => false,
                'verify_peer_name' => false,
            ],
        ];

        $context = stream_context_create($contextOptions);
        $socket = stream_socket_client("{$this->encryption}://{$this->host}:{$this->port}", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);
        if (!$socket) {
            throw new Exception("SMTP Connection failed: $errstr ($errno)");
        }

        // SMTP handshake
        $this->write($socket, "EHLO " . $this->host);

        // Authentication
        $this->write($socket, "AUTH LOGIN");
        $this->write($socket, base64_encode($this->username));
        $this->write($socket, base64_encode($this->password));

        // Mail setup
        $this->write($socket, "MAIL FROM:<{$this->fromEmail}>");
        $this->write($socket, "RCPT TO:<{$to}>");
        $this->write($socket, "DATA");

        // Construct email headers and body
        $emailData = "From: {$this->fromName} <{$this->fromEmail}>\r\n";
        $emailData .= "To: {$to}\r\n";
        $emailData .= "Subject: {$subject}\r\n";

        // Append additional headers (cleaned)
        if (!empty($headers)) {
            $emailData .= trim($headers) . "\r\n";
        }

        $emailData .= "\r\n"; // Separate headers and body
        $emailData .= $message . "\r\n.\r\n";

        $this->write($socket, $emailData);
        $this->write($socket, "QUIT");

        fclose($socket);
        return true;
    }

    private function write($socket, $data)
    {
        fputs($socket, $data . "\r\n");
        $this->read($socket);
    }

    private function read($socket)
    {
        $response = '';
        while ($line = fgets($socket, 512)) {
            $response .= $line;
            if (substr($line, 3, 1) === ' ') {
                break;
            }
        }
        return $response;
    }
}

// Custom mail wrapper
function customMail($to, $subject, $message, $headers)
{
    try {
        // Create an instance of SRNMailer
        $mailer = new SRNMailer();

        // Pass all arguments directly to the sendMail method
        return $mailer->sendMail($to, $subject, $message, $headers);
    } catch (Exception $e) {
        // Log the error and return false if the mail fails
        error_log("Mail error: " . $e->getMessage());
        return false;
    }
}
?>
