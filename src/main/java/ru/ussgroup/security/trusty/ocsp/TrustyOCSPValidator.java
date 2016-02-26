package ru.ussgroup.security.trusty.ocsp;

import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import ru.ussgroup.security.trusty.exception.TrustyOCSPCertificateException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPNonceException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPNotAvailableException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPUnknownProblemException;
import ru.ussgroup.security.trusty.repository.TrustyRepository;

public interface TrustyOCSPValidator {
    CompletableFuture<TrustyOCSPValidationResult> validateAsync(Set<X509Certificate> certs);
    
    TrustyOCSPValidationResult validate(Set<X509Certificate> certs) throws TrustyOCSPNotAvailableException, TrustyOCSPNonceException, TrustyOCSPCertificateException, TrustyOCSPUnknownProblemException;
    
    TrustyRepository getRepository();
}
