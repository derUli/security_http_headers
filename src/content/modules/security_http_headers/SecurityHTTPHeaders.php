<?php

class SecurityHTTPHeaders extends Controller
{

    public function beforeInit()
    {
        if (Request::isSSL() and ! $this->headerSent("Strict-Transport-Security")) {
            header('Strict-Transport-Security: max-age=16070400; includeSubDomains');
        }
        if (! $this->headerSent("X-Frame-Options")) {
            header('X-Frame-Options: SAMEORIGIN');
        }
        if (! $this->headerSent("X-XSS-Protection")) {
            header('X-XSS-Protection: 1; mode=block');
        }
        if (! $this->headerSent("X-Content-Type-Options")) {
            header('X-Content-Type-Options: nosniff');
        }
        if (! $this->headerSent("Referrer-Policy")) {
            header("Referrer-Policy: no-referrer-when-downgrade");
        }
        
        // **PREVENTING SESSION HIJACKING**
        // Prevents javascript XSS attacks aimed to steal the session ID
        ini_set('session.cookie_httponly', 1);
        
        // **PREVENTING SESSION FIXATION**
        // Session ID cannot be passed through URLs
        ini_set('session.use_only_cookies', 1);
        
        // Uses a secure connection (HTTPS) if possible
        ini_set('session.cookie_secure', 1);
    }

    private function headerSent($header)
    {
        $headers = headers_list();
        $header = trim($header, ': ');
        $result = false;
        
        foreach ($headers as $hdr) {
            if (stripos($hdr, $header) !== false) {
                $result = true;
            }
        }
        
        return $result;
    }
}
