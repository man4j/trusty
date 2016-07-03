package ru.ussgroup.security.trusty;

import java.math.BigInteger;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.internal.verification.VerificationModeFactory;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import ru.ussgroup.security.trusty.certpath.CertPathResult;
import ru.ussgroup.security.trusty.certpath.TrustyCachedCertPathValidator;
import ru.ussgroup.security.trusty.certpath.TrustyCertPathValidator;

public class TrustyCachedCertPathValidatorTest {
    TrustyCertPathValidator validatorMock;
    
    TrustyCachedCertPathValidator cachedValidator;
    
    Cache<BigInteger, CertPathResult> certificateCertPathStatusCache = CacheBuilder.newBuilder().maximumSize(50_000).build();
    
    X509Certificate gostCert = TrustyUtils.loadCredentialFromResources("/example/ul_gost_1.0.p12", "123456").getCertificate();
    
    Date date = new Date(gostCert.getNotBefore().getTime());
    
    @Before
    public void initValidator() {
        validatorMock = Mockito.mock(TrustyCertPathValidator.class);
        
        cachedValidator = new TrustyCachedCertPathValidator(validatorMock);
        
        cachedValidator.setCertificateCertPathStatusCache(certificateCertPathStatusCache);
    }
    
    @Test(expected = CertificateExpiredException.class)
    public void shouldThrowsExpired() throws Throwable {
        cachedValidator.validate(gostCert, date);
        
        Assert.assertEquals(1, certificateCertPathStatusCache.size());
        Assert.assertNotNull(certificateCertPathStatusCache.getIfPresent(gostCert.getSerialNumber()));
        
        Exception expected = null;
        
        try {
            cachedValidator.validate(gostCert, new Date(Long.MAX_VALUE));
        } catch (Exception e) {
            expected = e;
        }
        
        Assert.assertEquals(0, certificateCertPathStatusCache.size());
        Assert.assertNull(certificateCertPathStatusCache.getIfPresent(gostCert.getSerialNumber()));
        
        if (expected != null) {
            throw expected;
        }
    }
    
    @Test
    public void shouldCache() throws Throwable {
        cachedValidator.validate(gostCert, date);
        cachedValidator.validate(gostCert, date);
        cachedValidator.validate(gostCert, date);
        
        Mockito.verify(validatorMock, VerificationModeFactory.times(1)).validate(gostCert, date);
        Mockito.verify(validatorMock, VerificationModeFactory.times(0)).validate(gostCert);
        
        Assert.assertEquals(1, certificateCertPathStatusCache.size());
    }
    
    @Test
    public void shouldNotPinCertificateInCache() throws Throwable {
        cachedValidator.validate(gostCert, date);
        cachedValidator.validate(gostCert, date);
        cachedValidator.validate(FalsifyUtils.falsifyCert(gostCert), date);
        cachedValidator.validate(FalsifyUtils.falsifyCert(gostCert), date);
        cachedValidator.validate(gostCert, date);
        cachedValidator.validate(gostCert, date);
        cachedValidator.validate(FalsifyUtils.falsifyCert(gostCert), date);
        cachedValidator.validate(FalsifyUtils.falsifyCert(gostCert), date);
        
        Mockito.verify(validatorMock, VerificationModeFactory.times(2)).validate(gostCert, date);
        Mockito.verify(validatorMock, VerificationModeFactory.times(2)).validate(FalsifyUtils.falsifyCert(gostCert), date);
        Mockito.verify(validatorMock, VerificationModeFactory.times(0)).validate(gostCert);
        
        Assert.assertEquals(1, certificateCertPathStatusCache.size());
    }
}
