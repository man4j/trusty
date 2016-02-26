package ru.ussgroup.security.trusty;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class TrustyKeyUsageChecker {
    public static List<TrustyKeyUsage> getKeyUsage(X509Certificate cert) {
        boolean[] usages = cert.getKeyUsage();
        
        List<TrustyKeyUsage> list = new ArrayList<>();
        
        if ((usages[0]) && (usages[1])) list.add(TrustyKeyUsage.SIGNING);
        if ((usages[0]) && (usages[2])) list.add(TrustyKeyUsage.AUTHENTICATION);
        
        return list;
    }
}
