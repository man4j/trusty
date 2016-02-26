package ru.ussgroup.security.trusty.ocsp.kalkan;

import java.util.concurrent.CompletableFuture;

import kz.gov.pki.kalkan.ocsp.OCSPResp;

public class KalkanOCSPResponse {
    private final byte[] nonce;
    
    private final CompletableFuture<OCSPResp> futureResponse;
    
    public KalkanOCSPResponse(byte[] nonce, CompletableFuture<OCSPResp> futureResponse) {
        this.nonce = nonce;
        this.futureResponse = futureResponse;
    }
    
    public byte[] getNonce() {
        return nonce;
    }
    
    public CompletableFuture<OCSPResp> getFutureResponse() {
        return futureResponse;
    }
}
