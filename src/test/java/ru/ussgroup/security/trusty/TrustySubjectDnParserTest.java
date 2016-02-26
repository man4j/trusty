package ru.ussgroup.security.trusty;

import java.security.cert.X509Certificate;

import org.junit.Assert;
import org.junit.Test;


public class TrustySubjectDnParserTest {
    @Test
    public void shouldValidateCertificates() {
        X509Certificate oldGostCert = TrustyUtils.loadCredentialFromResources("/example/ul_gost_1.0.p12", "123456").getCertificate();
        X509Certificate newGostCert = TrustyUtils.loadCredentialFromResources("/example/ul_gost_2.0.p12", "123456").getCertificate();
        X509Certificate oldRsaCert = TrustyUtils.loadCredentialFromResources("/example/ul_rsa_1.0.p12", "123456").getCertificate();
        X509Certificate newRsaCert = TrustyUtils.loadCredentialFromResources("/example/ul_rsa_2.0.p12", "123456").getCertificate();
        
        Assert.assertNotNull(new TrustySubjectDNParser(oldGostCert.getSubjectDN()).getIin());
        Assert.assertNotNull(new TrustySubjectDNParser(newGostCert.getSubjectDN()).getIin());
        Assert.assertNotNull(new TrustySubjectDNParser(oldRsaCert.getSubjectDN()).getIin());
        Assert.assertNotNull(new TrustySubjectDNParser(newRsaCert.getSubjectDN()).getIin());
        
        Assert.assertNotNull(new TrustySubjectDNParser(oldGostCert.getSubjectDN()).getEmail());
        Assert.assertNotNull(new TrustySubjectDNParser(oldRsaCert.getSubjectDN()).getEmail());
        
        Assert.assertNull(new TrustySubjectDNParser(newRsaCert.getSubjectDN()).getEmail());//в новых сертификатах нет email?
        Assert.assertNull(new TrustySubjectDNParser(newGostCert.getSubjectDN()).getEmail());
    }
}
