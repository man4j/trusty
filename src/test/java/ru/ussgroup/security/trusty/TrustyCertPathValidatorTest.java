package ru.ussgroup.security.trusty;

import java.security.SignatureException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import ru.ussgroup.security.trusty.repository.TrustyKeyStoreRepository;
import ru.ussgroup.security.trusty.repository.TrustyRepository;

//Если для загрузки сертификатов использовать провайдер Kalkan, то данные тесте не проходят.
//Неужели глюки в Калкане?
public class TrustyCertPathValidatorTest {
    private static TrustyCertPathValidator validator;
    
    @BeforeClass
    public static void initValidator() {
        TrustyRepository repository = new TrustyKeyStoreRepository("/ca/kalkan_repository.jks");
        
        validator = new TrustyCertPathValidator(repository);
    }
    
    @Test(expected = SignatureException.class)
    public void shouldValidateCertificates() throws Throwable {
        X509Certificate oldGostCert = TrustyUtils.loadCredentialFromResources("/example/ul_gost_1.0.p12", "123456").getCertificate();
        X509Certificate newGostCert = TrustyUtils.loadCredentialFromResources("/example/ul_gost_2.0.p12", "123456").getCertificate();
        X509Certificate oldRsaCert = TrustyUtils.loadCredentialFromResources("/example/ul_rsa_1.0.p12", "123456").getCertificate();
        X509Certificate newRsaCert = TrustyUtils.loadCredentialFromResources("/example/ul_rsa_2.0.p12", "123456").getCertificate();
        
        validator.validate(oldGostCert);
        validator.validate(newGostCert);
        validator.validate(oldRsaCert);
        validator.validate(newRsaCert);
        
        byte[] bytes = oldGostCert.getEncoded();
        
        int index = 0;
        
        for (int i = 0; i < bytes.length; i++) {
            byte b = bytes[i];
            
            if (b == (byte) '@') {
                index = i;
                break;
            }
        }
        
        bytes[index] = '$';//подделываем сертификат
        
        String base64 = new String(Base64.getEncoder().encode(bytes));
        
        X509Certificate cert = TrustyUtils.loadFromString(base64);
        
        validator.validate(cert);
    }
    
    @Test(expected = CertificateExpiredException.class)
    public void shouldThrowExceptionIfExpired() throws CertificateNotYetValidException, CertificateExpiredException, SignatureException, CertPathValidatorException {
        X509Certificate oldExpiredRsaCert = TrustyUtils.loadCredentialFromResources("/example/ul_rsa_1.0_expired.p12", "123456").getCertificate();
        
        validator.validate(oldExpiredRsaCert);
    }
    
    @Test
    public void shouldParallelValidateOldGostCert() throws Exception {
        X509Certificate cert = TrustyUtils.loadCredentialFromResources("/example/ul_gost_1.0.p12", "123456").getCertificate();
        
        shouldParallelValidateOldCertificates(cert);
    }
    
    @Test
    public void shouldParallelValidateOldRsaCert() throws Exception {
        X509Certificate cert = TrustyUtils.loadCredentialFromResources("/example/ul_rsa_1.0.p12", "123456").getCertificate();
        
        shouldParallelValidateOldCertificates(cert);
    }
    
    @Test
    public void shouldParallelValidateNewGostCert() throws Exception {
        X509Certificate cert = TrustyUtils.loadCredentialFromResources("/example/ul_gost_2.0.p12", "123456").getCertificate();
        
        shouldParallelValidateOldCertificates(cert);
    }
    
    @Test
    public void shouldParallelValidateNewRsaCert() throws Exception {
        X509Certificate cert = TrustyUtils.loadCredentialFromResources("/example/ul_rsa_2.0.p12", "123456").getCertificate();
        
        shouldParallelValidateOldCertificates(cert);
    }
    
    public void shouldParallelValidateOldCertificates(X509Certificate cert) throws Exception {
        List<Thread> threads = new ArrayList<>();
        
        final AtomicBoolean successful = new AtomicBoolean(true);
        
        TrustyRepository repository = new TrustyKeyStoreRepository("/ca/kalkan_repository.jks");
        
        TrustyCertPathValidator validator = new TrustyCertPathValidator(repository);
        
        for (int i = 0; i < 1_00; i++) {
            Thread t = new Thread() {
                @Override
                public void run() {
                    try {
                        for (int i = 0; i < 1_000; i++) {
                            validator.validate(cert);
                        }
                    } catch (Exception e) {
                        successful.set(false);
                        e.printStackTrace();
                    }
                }
            };

            t.start();
            threads.add(t);
        }
        
        for (Thread t : threads) {
            t.join();
        }
        
        Assert.assertTrue("At least one thread execution failed", successful.get());
    }
}
