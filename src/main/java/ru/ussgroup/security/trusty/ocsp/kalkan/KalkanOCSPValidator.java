package ru.ussgroup.security.trusty.ocsp.kalkan;

import java.net.UnknownHostException;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import kz.gov.pki.kalkan.ocsp.OCSPResp;
import ru.ussgroup.security.trusty.exception.TrustyOCSPCertificateException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPNonceException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPNotAvailableException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPUnknownProblemException;
import ru.ussgroup.security.trusty.ocsp.TrustyOCSPValidationResult;
import ru.ussgroup.security.trusty.ocsp.TrustyOCSPValidator;
import ru.ussgroup.security.trusty.repository.TrustyRepository;
import ru.ussgroup.security.trusty.utils.ExceptionHandler;

/**
 * This class is thread-safe
 */
public class KalkanOCSPValidator implements TrustyOCSPValidator {
    private final KalkanOCSPRequestSender kalkanOCSPRequestSender;
    
    private final KalkanOCSPResponseChecker kalkanOCSPResponseChecker;
    
    public KalkanOCSPValidator(String ocspUrl, String ip, TrustyRepository trustyRepository) throws UnknownHostException {
        kalkanOCSPRequestSender = new KalkanOCSPRequestSender(ocspUrl, ip, trustyRepository);
        kalkanOCSPResponseChecker = new KalkanOCSPResponseChecker(trustyRepository);
    }
    
    @Override
    public CompletableFuture<TrustyOCSPValidationResult> validateAsync(Set<X509Certificate> certs) {
        KalkanOCSPResponse r = kalkanOCSPRequestSender.sendRequest(certs);

        return r.getFutureResponse().thenApplyAsync((OCSPResp ocspResp) -> {//проверяем асинхронно, т.к. checkResponse тяжелый метод из-за проверки сертификата OCSP
            try {
                return kalkanOCSPResponseChecker.checkResponse(ocspResp, r.getNonce());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Override
    public TrustyOCSPValidationResult validate(Set<X509Certificate> certs) throws TrustyOCSPNotAvailableException, TrustyOCSPNonceException, TrustyOCSPCertificateException, TrustyOCSPUnknownProblemException {
        return ExceptionHandler.handleFutureResult(validateAsync(certs));
    }
    
    @Override
    public TrustyRepository getRepository() {
        return kalkanOCSPRequestSender.getRepository();
    }
}
