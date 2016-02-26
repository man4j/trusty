package ru.ussgroup.security.trusty.ocsp;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import ru.ussgroup.security.trusty.exception.TrustyOCSPCertificateException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPNonceException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPNotAvailableException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPUnknownProblemException;
import ru.ussgroup.security.trusty.repository.TrustyRepository;
import ru.ussgroup.security.trusty.utils.ExceptionHandler;

/**
 * This class is thread-safe
 */
public class TrustyCachedOCSPValidator implements TrustyOCSPValidator {
    private final Cache<BigInteger, TrustyOCSPStatus> certificateStatusCache;
    
    private final Cache<BigInteger, TrustyOCSPStatus> trustedCertificateStatusCache;
    
    private final TrustyOCSPValidator validator;
    
    public TrustyCachedOCSPValidator(TrustyOCSPValidator validator, int cachedTime, int trustedCachedTime) {
        this.validator = validator;
        certificateStatusCache = CacheBuilder.newBuilder().maximumSize(50_000)
                                                          .expireAfterWrite(cachedTime, TimeUnit.MINUTES)
                                                          .build();
        
        trustedCertificateStatusCache = CacheBuilder.newBuilder().maximumSize(1_000)
                                                                 .expireAfterWrite(trustedCachedTime, TimeUnit.MINUTES)
                                                                 .build();
    }
    
    @Override
    public CompletableFuture<TrustyOCSPValidationResult> validateAsync(Set<X509Certificate> certs) {
        Map<BigInteger, TrustyOCSPStatus> statuses = new HashMap<>();
        
        Set<X509Certificate> toProcess = new HashSet<>(certs);
        
        Iterator<X509Certificate> it = toProcess.iterator();
        
        while (it.hasNext()) {
            X509Certificate checkedCert = it.next();
            
            TrustyOCSPStatus status = trustedCertificateStatusCache.getIfPresent(checkedCert.getSerialNumber());
            
            if (status == null) status = certificateStatusCache.getIfPresent(checkedCert.getSerialNumber());
            
            if (status != null) {
                statuses.put(checkedCert.getSerialNumber(), status);
                it.remove();
            }
        }
        
        return validator.validateAsync(toProcess).thenApply(validationResult -> {
            List<X509Certificate> trustedAndIntermediateCerts = new ArrayList<>(validator.getRepository().getTrustedCerts());
            
            trustedAndIntermediateCerts.addAll(validator.getRepository().getIntermediateCerts());
            
            Map<BigInteger, TrustyOCSPStatus> freshStatuses = validationResult.getStatuses();
            
            for (X509Certificate checkedCert : toProcess) {
                TrustyOCSPStatus status = freshStatuses.get(checkedCert.getSerialNumber());
                
                Cache<BigInteger, TrustyOCSPStatus> cache = certificateStatusCache;
                
                for (X509Certificate trustedCert : trustedAndIntermediateCerts) {
                    if (trustedCert.getSerialNumber().equals(checkedCert.getSerialNumber())) {
                        cache = trustedCertificateStatusCache;
                        
                        break;
                    }
                }
                
                cache.put(checkedCert.getSerialNumber(), status);
            }
            
            statuses.putAll(freshStatuses);
            
            return new TrustyOCSPValidationResult(validationResult.getResponse(), statuses);
        });
    }

    @Override
    public TrustyOCSPValidationResult validate(Set<X509Certificate> certs) throws TrustyOCSPNotAvailableException, TrustyOCSPNonceException, TrustyOCSPCertificateException, TrustyOCSPUnknownProblemException {
        return ExceptionHandler.handleFutureResult(validateAsync(certs));
    }
    
    @Override
    public TrustyRepository getRepository() {
        return validator.getRepository();
    }
}
