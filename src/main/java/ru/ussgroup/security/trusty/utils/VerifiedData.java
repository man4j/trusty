package ru.ussgroup.security.trusty.utils;

import ru.ussgroup.security.trusty.TrustyCertValidationCode;

public class VerifiedData {
    private SignedData signedData;
    
    private boolean valid = true;
    
    private TrustyCertValidationCode certStatus;

    public VerifiedData(SignedData signedData) {
        this.signedData = signedData;
    }

    public VerifiedData(SignedData signedData, boolean valid, TrustyCertValidationCode certStatus) {
        this.signedData = signedData;
        this.valid = valid;
        this.certStatus = certStatus;
    }

    public SignedData getSignedData() {
        return signedData;
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
}
