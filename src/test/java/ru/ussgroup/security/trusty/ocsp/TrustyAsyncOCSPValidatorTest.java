package ru.ussgroup.security.trusty.ocsp;

import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.security.auth.x500.X500PrivateCredential;

import org.junit.Assert;
import org.junit.Test;

import com.google.common.collect.ImmutableSet;

import ru.ussgroup.security.trusty.TrustyCertPathValidator;
import ru.ussgroup.security.trusty.TrustyCertificateValidator;
import ru.ussgroup.security.trusty.TrustySignatureVerifier;
import ru.ussgroup.security.trusty.TrustyUtils;
import ru.ussgroup.security.trusty.exception.TrustyOCSPCertificateException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPNonceException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPNotAvailableException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPUnknownProblemException;
import ru.ussgroup.security.trusty.ocsp.kalkan.KalkanOCSPValidator;
import ru.ussgroup.security.trusty.repository.TrustyKeyStoreRepository;
import ru.ussgroup.security.trusty.repository.TrustyRepository;
import ru.ussgroup.security.trusty.utils.SignedData;

public class TrustyAsyncOCSPValidatorTest {
    @Test
    public void shouldValidate() throws Exception {
        X509Certificate oldGostCert       = TrustyUtils.loadCredentialFromResources("/example/ul_gost_1.0.p12", "123456").getCertificate();
        X509Certificate oldRsaCert        = TrustyUtils.loadCredentialFromResources("/example/ul_rsa_1.0.p12",  "123456").getCertificate();
        X509Certificate oldRsaExpiredCert = TrustyUtils.loadCredentialFromResources("/example/ul_rsa_1.0_expired.p12",  "123456").getCertificate();
        X509Certificate oldRsaRevokedCert = TrustyUtils.loadCredentialFromResources("/example/ul_rsa_1.0_revoked.p12",  "123456").getCertificate();
        X509Certificate newRsaCert        = TrustyUtils.loadCredentialFromResources("/example/ul_rsa_2.0.p12",  "123456").getCertificate();
        X509Certificate newGostCert       = TrustyUtils.loadCredentialFromResources("/example/ul_gost_2.0.p12", "123456").getCertificate();
        
        X509Certificate kucGOST           = TrustyUtils.loadCertFromResources("/ca/kuc_gost_1.0.crt");
        X509Certificate kucRSA            = TrustyUtils.loadCertFromResources("/ca/kuc_rsa_1.0.crt");
        
        X509Certificate nucGOST2          = TrustyUtils.loadCertFromResources("/ca/nuc_gost_2.0.crt");
        X509Certificate nucRSA2           = TrustyUtils.loadCertFromResources("/ca/nuc_rsa_2.0.crt");
        
        X509Certificate nucGOST1          = TrustyUtils.loadCertFromResources("/ca/nuc_gost_1.0.cer");
        X509Certificate nucRSA1           = TrustyUtils.loadCertFromResources("/ca/nuc_rsa_1.0.cer");
        
        TrustyRepository repository = new TrustyKeyStoreRepository("/ca/kalkan_repository.jks");
        
        TrustyOCSPValidator validator = new TrustyCachedOCSPValidator(new KalkanOCSPValidator("http://ocsp.pki.gov.kz/ocsp/", "178.89.4.171", repository), 5, 60);
        
        TrustyOCSPValidationResult result = validator.validateAsync(ImmutableSet.of(oldGostCert, oldRsaCert, oldRsaExpiredCert, oldRsaRevokedCert, newRsaCert, newGostCert)).get();

        Assert.assertEquals(TrustyOCSPStatus.GOOD,    result.getStatuses().get(oldGostCert.getSerialNumber()).getStatus());
        Assert.assertEquals(TrustyOCSPStatus.GOOD,    result.getStatuses().get(oldRsaCert.getSerialNumber()).getStatus());
        Assert.assertEquals(TrustyOCSPStatus.GOOD,    result.getStatuses().get(oldRsaExpiredCert.getSerialNumber()).getStatus());
        Assert.assertEquals(TrustyOCSPStatus.REVOKED, result.getStatuses().get(oldRsaRevokedCert.getSerialNumber()).getStatus());
        Assert.assertEquals(TrustyOCSPStatus.GOOD,    result.getStatuses().get(newRsaCert.getSerialNumber()).getStatus());
        Assert.assertEquals(TrustyOCSPStatus.GOOD,    result.getStatuses().get(newGostCert.getSerialNumber()).getStatus());
        
        result = validator.validateAsync(ImmutableSet.of(kucGOST, kucRSA, nucGOST2, nucRSA2, nucGOST1, nucRSA1)).get();
        
        Assert.assertEquals(TrustyOCSPStatus.GOOD,    result.getStatuses().get(nucGOST1.getSerialNumber()).getStatus());
        Assert.assertEquals(TrustyOCSPStatus.GOOD,    result.getStatuses().get(nucRSA1.getSerialNumber()).getStatus());
        //Интересно почему статус UNKNOWN ? Похоже НУЦ не юзнает свои новые сертификаты.
        Assert.assertEquals(TrustyOCSPStatus.UNKNOWN, result.getStatuses().get(kucGOST.getSerialNumber()).getStatus());
        Assert.assertEquals(TrustyOCSPStatus.UNKNOWN, result.getStatuses().get(kucRSA.getSerialNumber()).getStatus());
        Assert.assertEquals(TrustyOCSPStatus.UNKNOWN, result.getStatuses().get(nucGOST2.getSerialNumber()).getStatus());
        Assert.assertEquals(TrustyOCSPStatus.UNKNOWN, result.getStatuses().get(nucRSA2.getSerialNumber()).getStatus());
    }
    
    @Test(expected = TrustyOCSPNotAvailableException.class)
    public void shouldSyncVerifySignature() throws TrustyOCSPNotAvailableException, TrustyOCSPNonceException, TrustyOCSPCertificateException, TrustyOCSPUnknownProblemException, UnknownHostException {
        TrustyRepository repository = new TrustyKeyStoreRepository("/ca/kalkan_repository.jks");
        
        TrustyCertPathValidator certPathValidator = new TrustyCertPathValidator(repository);
        
        TrustyOCSPValidator kalkanOCSPValidator = new KalkanOCSPValidator("http://1.1.1.1", "178.89.4.149", repository);
        
        TrustyOCSPValidator cachedOCSPValidator = new TrustyCachedOCSPValidator(kalkanOCSPValidator, 5, 60);
        
        TrustyCertificateValidator certificateValidator = new TrustyCertificateValidator(certPathValidator, cachedOCSPValidator);
        
        TrustySignatureVerifier signatureVerifier = new TrustySignatureVerifier(certificateValidator);
        
        X500PrivateCredential cert = TrustyUtils.loadCredentialFromResources("/example/ul_gost_1.0.p12", "123456");
        
        byte[] data = "Привет!".getBytes(StandardCharsets.UTF_8);
        
        byte[] signature;
        try {
            signature = TrustyUtils.sign(data, cert.getPrivateKey());
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
        
        signatureVerifier.verify(Arrays.asList(new SignedData(data, signature, cert.getCertificate())));
    }
}
