package ru.ussgroup.security.trusty;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;

import javax.security.auth.x500.X500PrivateCredential;

import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import ru.ussgroup.security.trusty.repository.TrustyRepository;

/*
 * getExtendedKeyUsage

1.3.6.1.5.5.7.3.2 - проверка подлинности клиента
1.2.398.5.19.1.2.2.1 - казначейство клиент или нотариат (необходимо исключить использование данных сертификатов)
1.2.398.6.1.1.1.1 - нотариат (необходимо исключить использование данных сертификатов)
*1.2.398.3.3.4.1.1 - физическое лицо
*1.2.398.3.3.4.1.2 - юридическое лицо
*1.2.398.3.3.4.1.2.1 – Первый руководитель
*1.2.398.3.3.4.1.2.2 – Лицо, наделенное правом подписи
*1.2.398.3.3.4.1.2.3 - Лицо, наделенное правом подписи финансовых документов
*1.2.398.3.3.4.1.2.5 – Сотрудник организации

* - только в новых сертификатах

Новые сертификаты с новым OID:
Политики действия сертификатов (одинаковая для старых и для новых сертификатов):

1.2.398.3.3.1.1 Регламент Национального удостоверяющего центра Республики Казахстан
1.2.398.3.3.2.1 Политика применения регистрационных свидетельств электронной цифровой подписи юридических лиц Республики Казахстан
1.2.398.3.3.2.2 Политика применения регистрационных свидетельств аутентификации юридических лиц Республики Казахстан
1.2.398.3.3.2.3 Политика применения регистрационных свидетельств электронной цифровой подписи физических лиц Республики Казахстан
1.2.398.3.3.2.4 Политика применения регистрационных свидетельств аутентификации физических лиц Республики Казахстан
*/
public class TrustyUtils {
    static {
        if (Security.getProvider(KalkanProvider.PROVIDER_NAME) == null) Security.addProvider(new KalkanProvider());
    }
    
    public static List<X509Certificate> getCertPath(X509Certificate cert, TrustyRepository repository) {
        List<X509Certificate> list = new ArrayList<>();
        
        list.add(cert);
        
        X509Certificate current = cert;
        
        while (true) {        
            X509Certificate x509IntermediateCert = repository.getIntermediateCert(current);
            
            if (x509IntermediateCert != null) {
                list.add(x509IntermediateCert);
                
                current = x509IntermediateCert;
            } else {
                break;
            }
        }
        
        return list;
    }
    
    public static List<X509Certificate> getFullCertPath(X509Certificate cert, TrustyRepository repository) {
        List<X509Certificate> list = getCertPath(cert, repository);
        
        list.add(repository.getTrustedCert(list.get(list.size() - 1)));
        
        return list;
    }
    
    public static String sign(String data, PrivateKey privateKey) throws SignatureException {
        return Base64.getEncoder().encodeToString(sign(data.getBytes(StandardCharsets.UTF_8), privateKey));
    }
    
    public static byte[] sign(byte[] data, PrivateKey privateKey) throws SignatureException {
        try {
            Signature signature = Signature.getInstance(privateKey.getAlgorithm());
            
            signature.initSign(privateKey);
            signature.update(data);
            
            return signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
    
    public static X509Certificate loadCertFromResources(String path) {
        try (InputStream in = TrustyUtils.class.getResourceAsStream(path)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    
    public static X509Certificate loadCertFromFile(String path) {
        try (InputStream in = new FileInputStream(path)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    
    public static X500PrivateCredential loadCredentialFromResources(String path, String password) {
        try {
            KeyStore keyStore = KeyStore.getInstance("pkcs12");
            
            try (InputStream in = TrustyUtils.class.getResourceAsStream(path)) {
                return loadCredentialFromStream(password, keyStore, in);
            } 
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    
    public static X500PrivateCredential loadCredentialFromFile(String path, String password) {
        try {
            KeyStore keyStore = KeyStore.getInstance("pkcs12");
            
            try (InputStream in = new FileInputStream(path)) {
                return loadCredentialFromStream(password, keyStore, in);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    
    public static String toBase64(X509Certificate certificate) throws CertificateEncodingException {
        return new String(Base64.getEncoder().encode(certificate.getEncoded()));
    }

    public static String toBase64(Key key) {
        return new String(Base64.getEncoder().encode(key.getEncoded()));
    }
    
    public static X509Certificate loadFromString(String base64Encoded) throws CertificateParsingException {
        X509Certificate cert = null;
        
        try {
            cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(removeNewLines(base64Encoded))));
        } catch (Exception e) {
            throw new CertificateParsingException(e);
        }

        if (cert == null) throw new CertificateParsingException();

        return cert;
    }

    private static X500PrivateCredential loadCredentialFromStream(String password, KeyStore keyStore, InputStream in) {
        try {
            keyStore.load(in, password.toCharArray());
            
            Enumeration<String> aliases = keyStore.aliases();
            
            while (aliases.hasMoreElements()){
                String alias = aliases.nextElement();
                
                return new X500PrivateCredential((X509Certificate)keyStore.getCertificate(alias), 
                                                      (PrivateKey)keyStore.getKey(alias, password.toCharArray()));
            }
            
            return null;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    
    public static String removeNewLines(String s) {
        return s.replace("\r", "").replace("\n", "").replace(" ", "");
    }
}
