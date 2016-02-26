package ru.ussgroup.security.trusty.ocsp;

import java.math.BigInteger;
import java.util.Map;

public class TrustyOCSPValidationResult {
    private Object response;
    
    private Map<BigInteger, TrustyOCSPStatus> statuses;

    public TrustyOCSPValidationResult(Object response, Map<BigInteger, TrustyOCSPStatus> statuses) {
        this.response = response;
        this.statuses = statuses;
    }

    public Object getResponse() {
        return response;
    }

    public Map<BigInteger, TrustyOCSPStatus> getStatuses() {
        return statuses;
    }
}
