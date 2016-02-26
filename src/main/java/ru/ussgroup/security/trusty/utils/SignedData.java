package ru.ussgroup.security.trusty.utils;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Base64;

import ru.ussgroup.security.trusty.TrustyCertValidationCode;
import ru.ussgroup.security.trusty.TrustyUtils;

public class SignedData {
    private Object id;
    
    private byte[] data;
    
    private byte[] signature;
    
    private X509Certificate cert;
    
    private boolean valid = true;
    
    private TrustyCertValidationCode certStatus;
    
    public SignedData(String data, String signature, X509Certificate cert) {
        this(null, data, signature, cert);
    }
    
    public SignedData(Object id, String data, String signature, X509Certificate cert) {
        this(id, data.getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(TrustyUtils.removeNewLines(signature)), cert);
    }
    
    public SignedData(byte[] data, byte[] signature, X509Certificate cert) {
        this(null, data, signature, cert);
    }
    
    public SignedData(Object id, byte[] data, byte[] signature, X509Certificate cert) {
        this.data = data;
        this.signature = signature;
        this.cert = cert;
    }
    
    public byte[] getData() {
        return data;
    }

    public byte[] getSignature() {
        return signature;
    }

    public X509Certificate getCert() {
        return cert;
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }
    
    public TrustyCertValidationCode getCertStatus() {
        return certStatus;
    }

    public void setCertStatus(TrustyCertValidationCode certStatus) {
        this.certStatus = certStatus;
    }
    
    public Object getId() {
        return id;
    }
}
