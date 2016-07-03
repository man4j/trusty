package ru.ussgroup.security.trusty;

import java.security.cert.X509Certificate;
import java.util.Base64;

public class FalsifyUtils {
    public static X509Certificate falsifyCert(X509Certificate cert) {
        try {
            byte[] bytes = cert.getEncoded();
            
            int index = 0;
            
            for (int i = 0; i < bytes.length; i++) {
                byte b = bytes[i];
                
                if (b == (byte) '@') {
                    index = i;
                    break;
                }
            }
            
            bytes[index] = '$';//подделываем сертификат
            
            String base64 = new String(Base64.getEncoder().encode(bytes));
            
            return TrustyUtils.loadFromString(base64);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
