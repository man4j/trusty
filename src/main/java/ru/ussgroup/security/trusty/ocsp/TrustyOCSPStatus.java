package ru.ussgroup.security.trusty.ocsp;

import java.util.Date;

public class TrustyOCSPStatus {
    public static final int GOOD = 1;
    public static final int REVOKED = 2;
    public static final int UNKNOWN = 3;

    private int status;

    private Date revocationTime;

    private int revocationReason;
    
    public TrustyOCSPStatus(int status, Date revocationTime, int revocationReason) {
        this.status = status;
        this.revocationTime = revocationTime;
        this.revocationReason = revocationReason;
    }

    public TrustyOCSPStatus(int status) {
        this.status = status;
    }

    public int getStatus() {
        return status;
    }

    public Date getRevocationTime() {
        return revocationTime;
    }

    public int getRevocationReason() {
        return revocationReason;
    }
}
