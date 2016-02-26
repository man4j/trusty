package ru.ussgroup.security.trusty.exception;

public class TrustyOCSPCertificateException extends Exception {
    public TrustyOCSPCertificateException() {
        super();
    }

    public TrustyOCSPCertificateException(String message, Throwable cause) {
        super(message, cause);
    }

    public TrustyOCSPCertificateException(String message) {
        super(message);
    }

    public TrustyOCSPCertificateException(Throwable cause) {
        super(cause);
    }
}
