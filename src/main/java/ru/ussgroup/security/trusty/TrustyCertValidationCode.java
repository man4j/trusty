package ru.ussgroup.security.trusty;

public enum TrustyCertValidationCode {
    SUCCESS, 
    OCSP_FAILED, 
    CERT_PATH_FAILED,//Сертификат не прошел проверку по неизвестной причине 
    CERT_NOT_YET_VALID, 
    CERT_EXPIRED, 
    CERT_SIGNATURE_EXCEPTION,
    NOT_FOR_SIGNING
}
