package ru.ussgroup.security.trusty.utils;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import ru.ussgroup.security.trusty.exception.TrustyOCSPCertificateException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPNonceException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPNotAvailableException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPUnknownProblemException;

public class ExceptionHandler {
    public static <T> T handleFutureResult(Future<T> future) throws TrustyOCSPNotAvailableException, TrustyOCSPNonceException, TrustyOCSPCertificateException, TrustyOCSPUnknownProblemException {
        try {
            return future.get();
        } catch (InterruptedException | ExecutionException e) {
            Throwable originalException = e.getCause().getCause();
            
            try {
                throw originalException;
            } catch (TrustyOCSPNotAvailableException | TrustyOCSPNonceException | TrustyOCSPCertificateException | TrustyOCSPUnknownProblemException e1) {
                e1.fillInStackTrace();//for correct line number
                
                throw e1;
            } catch (Throwable e1) {
                throw new RuntimeException(e);
            }
        }
    }
}
