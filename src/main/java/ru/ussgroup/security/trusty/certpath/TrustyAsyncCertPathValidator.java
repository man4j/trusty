package ru.ussgroup.security.trusty.certpath;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import ru.ussgroup.security.trusty.TrustyCertValidationCode;

public interface TrustyAsyncCertPathValidator {
    CompletableFuture<Map<BigInteger, TrustyCertValidationCode>> validateAsync(Set<X509Certificate> certs);
    
    CompletableFuture<Map<BigInteger, TrustyCertValidationCode>> validateAsync(Set<X509Certificate> certs, Date date);
}
