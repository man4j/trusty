package ru.ussgroup.security.trusty.certpath;

import java.security.SignatureException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;

public interface TrustyCertPathValidator {
    void validate(X509Certificate cert) throws CertificateNotYetValidException, CertificateExpiredException, SignatureException, CertPathValidatorException;
    
    void validate(X509Certificate cert, Date date) throws CertificateNotYetValidException, CertificateExpiredException, SignatureException, CertPathValidatorException;
}
