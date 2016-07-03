package ru.ussgroup.security.trusty.certpath;

import java.security.SignatureException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.stream.Collectors;

import ru.ussgroup.security.trusty.TrustyUtils;
import ru.ussgroup.security.trusty.repository.TrustyRepository;

/**
 * This class is thread-safe 
 */
public class TrustyCertPathValidatorImpl implements TrustyCertPathValidator {
    final TrustyRepository repository;
    
    public TrustyCertPathValidatorImpl(TrustyRepository repository) {
        this.repository = repository;
    }
    
    @Override
    public void validate(X509Certificate cert) throws CertificateNotYetValidException, CertificateExpiredException, SignatureException, CertPathValidatorException {
        validate(cert, new Date());
    }
        
    /**
     * @param date null is disable expire date verification
     */
    @Override
    public void validate(X509Certificate cert, Date date) throws CertificateNotYetValidException, CertificateExpiredException, SignatureException, CertPathValidatorException {
        try {
            PKIXBuilderParameters params = new PKIXBuilderParameters(repository.getTrustedCerts().stream().map(c -> new TrustAnchor(c, null)).collect(Collectors.toSet()), null);
            params.setRevocationEnabled(false);
            
            params.setDate(date != null ? date : cert.getNotBefore());
        
            CertPathValidator.getInstance("PKIX").validate(CertificateFactory.getInstance("X.509").generateCertPath(TrustyUtils.getCertPath(cert, repository)), params);
        } catch (Exception e) {
            //CertificateNotYetValidException.getReason не поддерживается калканом ((
            if (e.getCause() != null) {
                if (e.getCause() instanceof CertificateNotYetValidException) {
                    CertificateNotYetValidException e1 = (CertificateNotYetValidException) e.getCause();
                    
                    throw e1;
                }
                
                if (e.getCause() instanceof CertificateExpiredException) {
                    CertificateExpiredException e1 = (CertificateExpiredException) e.getCause();
                    
                    throw e1;
                }
                
                if (e.getCause() instanceof SignatureException) {//почему-то в случае с подделкой сертификата вместо этого исключения стало выбрасываться CertPathValidatorException
                    SignatureException e1 = (SignatureException) e.getCause();
                    
                    throw e1;
                }
            }
            
            if (e instanceof CertPathValidatorException) {
                CertPathValidatorException e1 = (CertPathValidatorException) e;
                
                throw e1;
            }
            
            throw new CertPathValidatorException(e);
        }
    }
}
