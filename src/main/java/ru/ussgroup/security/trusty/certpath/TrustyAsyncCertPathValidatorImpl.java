package ru.ussgroup.security.trusty.certpath;

import java.math.BigInteger;
import java.security.SignatureException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import ru.ussgroup.security.trusty.TrustyCertValidationCode;

public class TrustyAsyncCertPathValidatorImpl implements TrustyAsyncCertPathValidator {
    private TrustyCertPathValidator validator;
    
    public TrustyAsyncCertPathValidatorImpl(TrustyCertPathValidator validator) {
        this.validator = validator;
    }

    @Override
    public CompletableFuture<Map<BigInteger, TrustyCertValidationCode>> validateAsync(Set<X509Certificate> certs) {
        return validateAsync(certs, new Date());
    }
    
    /**
     * @param date null is disable expire date verification
     */
    @Override
    public CompletableFuture<Map<BigInteger, TrustyCertValidationCode>> validateAsync(Set<X509Certificate> certs, Date date) {
        return CompletableFuture.supplyAsync(() -> {
            return certs.parallelStream().collect(Collectors.toConcurrentMap(X509Certificate::getSerialNumber, c -> {
                try {
                    validator.validate(c, date);
                    
                    return TrustyCertValidationCode.SUCCESS;
                } catch (CertificateNotYetValidException e) {
                    return TrustyCertValidationCode.CERT_NOT_YET_VALID;
                } catch (CertificateExpiredException e) {
                    return TrustyCertValidationCode.CERT_EXPIRED;
                } catch (SignatureException e) {
                    return TrustyCertValidationCode.CERT_SIGNATURE_EXCEPTION;
                } catch (CertPathValidatorException e) {
                    return TrustyCertValidationCode.CERT_PATH_FAILED;
                }
            }));
        });
    }
}
