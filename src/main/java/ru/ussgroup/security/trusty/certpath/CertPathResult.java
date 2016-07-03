package ru.ussgroup.security.trusty.certpath;

import java.security.cert.X509Certificate;

public class CertPathResult {
    private X509Certificate cert;
    
    private Exception exception;
    
    public CertPathResult(X509Certificate cert) {
        this.cert = cert;
    }

    public CertPathResult(X509Certificate cert, Exception exception) {
        this.cert = cert;
        this.exception = exception;
    }

    public X509Certificate getCert() {
        return cert;
    }

    public Exception getException() {
        return exception;
    }
}
