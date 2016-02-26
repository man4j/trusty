package ru.ussgroup.security.trusty.repository;

import java.security.cert.X509Certificate;
import java.util.Collection;

public interface TrustyRepository {
    Collection<X509Certificate> getTrustedCerts();
    
    Collection<X509Certificate> getIntermediateCerts();
    
    X509Certificate getTrustedCert(X509Certificate cert);

    X509Certificate getIntermediateCert(X509Certificate cert);
    
    X509Certificate getIssuer(X509Certificate cert);
}
