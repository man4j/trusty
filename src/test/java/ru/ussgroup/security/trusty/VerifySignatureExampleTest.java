package ru.ussgroup.security.trusty;

import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Future;

import javax.security.auth.x500.X500PrivateCredential;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import ru.ussgroup.security.trusty.certpath.TrustyAsyncCertPathValidator;
import ru.ussgroup.security.trusty.certpath.TrustyAsyncCertPathValidatorImpl;
import ru.ussgroup.security.trusty.certpath.TrustyCachedCertPathValidator;
import ru.ussgroup.security.trusty.certpath.TrustyCertPathValidatorImpl;
import ru.ussgroup.security.trusty.exception.TrustyOCSPCertificateException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPNonceException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPNotAvailableException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPUnknownProblemException;
import ru.ussgroup.security.trusty.ocsp.TrustyCachedOCSPValidator;
import ru.ussgroup.security.trusty.ocsp.TrustyOCSPValidator;
import ru.ussgroup.security.trusty.ocsp.kalkan.KalkanOCSPValidator;
import ru.ussgroup.security.trusty.repository.TrustyKeyStoreRepository;
import ru.ussgroup.security.trusty.repository.TrustyRepository;
import ru.ussgroup.security.trusty.utils.ExceptionHandler;
import ru.ussgroup.security.trusty.utils.SignedData;
import ru.ussgroup.security.trusty.utils.VerifiedData;

public class VerifySignatureExampleTest {
    private TrustySignatureVerifier signatureVerifier;
    
    @Before
    public void init() throws UnknownHostException {
        TrustyRepository repository = new TrustyKeyStoreRepository("/ca/kalkan_repository.jks");
        
        TrustyAsyncCertPathValidator asyncCachedCertPathValidator = new TrustyAsyncCertPathValidatorImpl(new TrustyCachedCertPathValidator(new TrustyCertPathValidatorImpl(repository)));
        
        TrustyOCSPValidator cachedOCSPValidator = new TrustyCachedOCSPValidator(new KalkanOCSPValidator("http://ocsp.pki.gov.kz/ocsp/", "178.89.4.171", repository), repository, 5, 60);
        
        TrustyCertificateValidator certificateValidator = new TrustyCertificateValidator(asyncCachedCertPathValidator, cachedOCSPValidator);
        
        signatureVerifier = new TrustySignatureVerifier(certificateValidator);
    }
    
    @Test
    public void shouldVerifySignature() throws Exception {
        X500PrivateCredential cert = TrustyUtils.loadCredentialFromResources("/example/ul_gost_2.0.p12", "123456");
        
        byte[] data = "Привет!".getBytes(StandardCharsets.UTF_8);
        
        byte[] signature;
        
        try {
            signature = TrustyUtils.sign(data, cert.getPrivateKey());
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
        
        Future<List<VerifiedData>> future = signatureVerifier.verifyAsync(Arrays.asList(new SignedData(data, signature, cert.getCertificate()),
                                                                                        new SignedData("qwe".getBytes(StandardCharsets.UTF_8), signature, cert.getCertificate())),
                                                                                        cert.getCertificate().getNotBefore());
        
        try {
            ExceptionHandler.handleFutureResult(future);
        } catch (TrustyOCSPNotAvailableException | TrustyOCSPNonceException | TrustyOCSPCertificateException | TrustyOCSPUnknownProblemException e) {
            //Обрабатываем ошибки связанные с сервисом OCSP. Как правило данные ошибки означают, что произошла не стандартная ситуация
            //требующая логирования и выяснения причин
            throw e;
        }
        
        List<VerifiedData> results = future.get();
        
        Assert.assertTrue(results.get(0).isValid());
        Assert.assertFalse(results.get(1).isValid());
    }
    
    @Test
    public void shouldSyncVerifySignature() throws TrustyOCSPNotAvailableException, TrustyOCSPNonceException, TrustyOCSPCertificateException, TrustyOCSPUnknownProblemException {
        X500PrivateCredential cert = TrustyUtils.loadCredentialFromResources("/example/ul_gost_2.0.p12", "123456");
        
        byte[] data = "Привет!".getBytes(StandardCharsets.UTF_8);
        
        byte[] signature;
        try {
            signature = TrustyUtils.sign(data, cert.getPrivateKey());
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
        
        List<VerifiedData> results = signatureVerifier.verify(Arrays.asList(new SignedData(data, signature, cert.getCertificate()),
                                                                            new SignedData("qwe".getBytes(StandardCharsets.UTF_8), signature, cert.getCertificate())),
                                                                            cert.getCertificate().getNotBefore());
        
        Assert.assertTrue(results.get(0).isValid());
        Assert.assertFalse(results.get(1).isValid());
    }
}
