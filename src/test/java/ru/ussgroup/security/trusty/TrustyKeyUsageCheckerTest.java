package ru.ussgroup.security.trusty;

import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;

public class TrustyKeyUsageCheckerTest {
    @Test
    public void shoulCheckKeyUsage() {
        X509Certificate oldGostCert = TrustyUtils.loadCredentialFromResources("/example/ul_gost_1.0.p12", "123456").getCertificate();
        X509Certificate newGostCert = TrustyUtils.loadCredentialFromResources("/example/ul_gost_2.0.p12", "123456").getCertificate();
        X509Certificate oldRsaCert = TrustyUtils.loadCredentialFromResources("/example/ul_rsa_1.0.p12", "123456").getCertificate();
        X509Certificate newRsaCert = TrustyUtils.loadCredentialFromResources("/example/ul_rsa_2.0.p12", "123456").getCertificate();
        
        Assert.assertEquals(Arrays.asList(TrustyKeyUsage.SIGNING), TrustyKeyUsageChecker.getKeyUsage(oldGostCert));
        Assert.assertEquals(Arrays.asList(TrustyKeyUsage.SIGNING), TrustyKeyUsageChecker.getKeyUsage(newGostCert));
        
        Assert.assertNotEquals(Arrays.asList(TrustyKeyUsage.AUTHENTICATION), TrustyKeyUsageChecker.getKeyUsage(oldGostCert));
        Assert.assertNotEquals(Arrays.asList(TrustyKeyUsage.AUTHENTICATION), TrustyKeyUsageChecker.getKeyUsage(newGostCert));
        
        Assert.assertNotEquals(Arrays.asList(TrustyKeyUsage.SIGNING), TrustyKeyUsageChecker.getKeyUsage(oldRsaCert));
        Assert.assertNotEquals(Arrays.asList(TrustyKeyUsage.SIGNING), TrustyKeyUsageChecker.getKeyUsage(newRsaCert));
        
        Assert.assertEquals(Arrays.asList(TrustyKeyUsage.AUTHENTICATION), TrustyKeyUsageChecker.getKeyUsage(oldRsaCert));
        Assert.assertEquals(Arrays.asList(TrustyKeyUsage.AUTHENTICATION), TrustyKeyUsageChecker.getKeyUsage(newRsaCert));
    }
}
