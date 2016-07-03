package ru.ussgroup.security.trusty.certpath;

import java.math.BigInteger;
import java.security.SignatureException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

public class TrustyCachedCertPathValidator implements TrustyCertPathValidator {
    private Cache<BigInteger, CertPathResult> certificateCertPathStatusCache;
    
    private TrustyCertPathValidator validator;
    
    public TrustyCachedCertPathValidator(TrustyCertPathValidator validator) {
        this(validator, 50_000);
    }
    
    public TrustyCachedCertPathValidator(TrustyCertPathValidator validator, int size) {
        this.validator = validator;
        
        certificateCertPathStatusCache = CacheBuilder.newBuilder().maximumSize(size).build();
    }
    
    public void setCertificateCertPathStatusCache(Cache<BigInteger, CertPathResult> certificateCertPathStatusCache) {
        this.certificateCertPathStatusCache = certificateCertPathStatusCache;
    }
    
    @Override
    public void validate(X509Certificate cert, Date date) throws CertificateNotYetValidException, CertificateExpiredException, SignatureException, CertPathValidatorException  {
        try {
            if (date != null) {
                cert.checkValidity(date);//Проверяем дату, т.к. время меняется
            }
        } catch (CertificateNotYetValidException | CertificateExpiredException e) {
            certificateCertPathStatusCache.invalidate(cert.getSerialNumber());
                        
            throw e;
        }
        
        if ((certificateCertPathStatusCache.getIfPresent(cert.getSerialNumber()) == null)//если в кеше нет
        || (!certificateCertPathStatusCache.getIfPresent(cert.getSerialNumber()).getCert().equals(cert))) {//или есть, но не совпадает
            
            Exception resultException = null;
            
            try {
                validator.validate(cert, date);
            } catch (CertificateNotYetValidException e) {
                resultException = e;
            } catch (CertificateExpiredException e) {
                resultException = e;
            } catch (SignatureException e) {
                resultException = e;
            } catch (CertPathValidatorException e) {
                resultException = e;
            }
        
            certificateCertPathStatusCache.put(cert.getSerialNumber(), new CertPathResult(cert, resultException));
        } else {
            CertPathResult result = certificateCertPathStatusCache.getIfPresent(cert.getSerialNumber());
            
            if (result.getException() != null) {
                if (result.getException() instanceof CertificateNotYetValidException) throw (CertificateNotYetValidException) result.getException();
                if (result.getException() instanceof CertificateExpiredException) throw (CertificateExpiredException) result.getException();
                if (result.getException() instanceof SignatureException) throw (SignatureException) result.getException();
                if (result.getException() instanceof CertPathValidatorException) throw (CertPathValidatorException) result.getException();
            }
        }
    }

    @Override
    public void validate(X509Certificate cert) throws CertificateNotYetValidException, CertificateExpiredException, SignatureException, CertPathValidatorException {
        validate(cert, new Date());
    }
}
