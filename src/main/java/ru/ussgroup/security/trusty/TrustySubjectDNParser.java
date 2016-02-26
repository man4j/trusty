package ru.ussgroup.security.trusty;

import java.security.Principal;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import kz.gov.pki.kalkan.asn1.DERSequence;
import kz.gov.pki.kalkan.asn1.DERSet;
import kz.gov.pki.kalkan.jce.X509Principal;
import sun.security.x509.AVA;
import sun.security.x509.X500Name;

@SuppressWarnings("restriction")
public class TrustySubjectDNParser {
    private Map<String, String> names = new HashMap<>();
    
    public TrustySubjectDNParser(Principal principal) {
        if (principal instanceof X500Name) {
            X500Name name = (X500Name) principal;
            
            for (AVA ava : name.allAvas()) {
                String key = ava.getObjectIdentifier().toString();
                String value = ava.getValueString();
                
                if (key.equals(X509Principal.SERIALNUMBER.getId())) {
                    names.put("SERIALNUMBER", value);
                }
                
                if (key.equals(X509Principal.OU.getId())) {
                    names.put("OU", value);
                }
                
                if (key.equals(X509Principal.CN.getId())) {
                    names.put("CN", value);
                }
                
                if (key.equals(X509Principal.EmailAddress.getId())) {
                    names.put("EMAILADDRESS", value);
                }
            }
        } else if (principal instanceof X509Principal) {
            X509Principal p = (X509Principal) principal;
            
            @SuppressWarnings("unchecked")
            Enumeration<DERSet> enumeration = ((DERSequence) p.getDERObject()).getObjects();
            
            while (enumeration.hasMoreElements()) {
                DERSet ds = enumeration.nextElement();
                
                DERSequence seq = (DERSequence) ds.getObjectAt(0);
                
                String key = seq.getObjectAt(0).toString();
                String value = seq.getObjectAt(1).toString();
                
                if (key.equals(X509Principal.SERIALNUMBER.getId())) {
                    names.put("SERIALNUMBER", value);
                }
                
                if (key.equals(X509Principal.OU.getId())) {
                    names.put("OU", value);
                }
                
                if (key.equals(X509Principal.CN.getId())) {
                    names.put("CN", value);
                }
                
                if (key.equals(X509Principal.EmailAddress.getId())) {
                    names.put("EMAILADDRESS", value);
                }
            }
        } else {
            String[] values = principal.getName().split(",");
            
            names = new HashMap<>();
            
            for (String value : values) {
                names.put(value.split("=")[0].trim(), value.split("=")[1].trim());
            }
        }
    }
    
    public String getIin() {
        return Optional.ofNullable(names.get("SERIALNUMBER")).map(s -> s.substring(3)).orElse(null);
    }
    
    public String getBin() {
        return Optional.ofNullable(names.get("OU")).map(s -> s.substring(3)).orElse(null);
    }
    
    public String getCommonName() {
        return names.get("CN");
    }
    
    public String getEmail() {
        return names.get("EMAILADDRESS");
    }
}
