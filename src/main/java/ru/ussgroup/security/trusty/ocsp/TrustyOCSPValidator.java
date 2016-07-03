package ru.ussgroup.security.trusty.ocsp;

import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

public interface TrustyOCSPValidator {
    CompletableFuture<TrustyOCSPValidationResult> validateAsync(Set<X509Certificate> certs);
}
