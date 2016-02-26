package ru.ussgroup.security.trusty;

import java.math.BigInteger;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import ru.ussgroup.security.trusty.exception.TrustyOCSPCertificateException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPNonceException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPNotAvailableException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPUnknownProblemException;
import ru.ussgroup.security.trusty.utils.ExceptionHandler;
import ru.ussgroup.security.trusty.utils.SignedData;

public class TrustySignatureVerifier {
    private TrustyCertificateValidator certificateValidator;

    public TrustySignatureVerifier(TrustyCertificateValidator certificateValidator) {
        this.certificateValidator = certificateValidator;
    }
    
    public List<SignedData> verify(List<SignedData> list) throws TrustyOCSPNotAvailableException, TrustyOCSPNonceException, TrustyOCSPCertificateException, TrustyOCSPUnknownProblemException {
        return verify(list, new Date());
    }
    
    /**
     * @param date null is disable expire date verification
     */
    public List<SignedData> verify(List<SignedData> list, Date date) throws TrustyOCSPNotAvailableException, TrustyOCSPNonceException, TrustyOCSPCertificateException, TrustyOCSPUnknownProblemException {
        return ExceptionHandler.handleFutureResult(verifyAsync(list, date));
    }
    
    public CompletableFuture<List<SignedData>> verifyAsync(List<SignedData> list) {
        return verifyAsync(list, new Date());
    }
    
    /**
     * @param date null is disable expire date verification
     */
    public CompletableFuture<List<SignedData>> verifyAsync(List<SignedData> list, Date date) {
        Set<X509Certificate> certs = list.stream().map(SignedData::getCert).collect(Collectors.toSet());
        
        CompletableFuture<Map<BigInteger, TrustyCertValidationCode>> certResultsFuture = certificateValidator.validateAsync(certs, date);
        
        CompletableFuture<List<SignedData>> dataResultsFuture = CompletableFuture.supplyAsync(() -> {
            return list.parallelStream().map(sd -> {
                try {
                    Signature s = Signature.getInstance(sd.getCert().getPublicKey().getAlgorithm());
                    
                    s.initVerify(sd.getCert().getPublicKey());
                    s.update(sd.getData());
                    
                    if (!TrustyKeyUsageChecker.getKeyUsage(sd.getCert()).contains(TrustyKeyUsage.SIGNING)) {
                        sd.setCertStatus(TrustyCertValidationCode.NOT_FOR_SIGNING);
                        throw new CertificateException();
                    }
                    
                    if (!s.verify(sd.getSignature())) {
                        throw new SignatureException();
                    }
                } catch (Exception e) {
                    sd.setValid(false);
                }
                
                return sd;
            }).collect(Collectors.toList());
        });
        
        return dataResultsFuture.thenCombine(certResultsFuture, (dataResult, certResult) -> {
            for (SignedData sd : dataResult) {
                TrustyCertValidationCode code = certResult.get(sd.getCert().getSerialNumber());
                
                if (code != TrustyCertValidationCode.SUCCESS) {
                    sd.setValid(false);
                    sd.setCertStatus(code);
                }
            }
            
            return dataResult;
        });
    }
}
