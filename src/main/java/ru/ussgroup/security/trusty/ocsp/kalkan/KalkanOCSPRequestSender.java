package ru.ussgroup.security.trusty.ocsp.kalkan;

import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import com.ning.http.client.AsyncCompletionHandler;
import com.ning.http.client.AsyncHttpClient;
import com.ning.http.client.AsyncHttpClientConfig;
import com.ning.http.client.ListenableFuture;
import com.ning.http.client.Response;

import kz.gov.pki.kalkan.asn1.DERObjectIdentifier;
import kz.gov.pki.kalkan.asn1.DEROctetString;
import kz.gov.pki.kalkan.asn1.ocsp.OCSPObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.x509.X509Extension;
import kz.gov.pki.kalkan.asn1.x509.X509Extensions;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.ocsp.CertificateID;
import kz.gov.pki.kalkan.ocsp.OCSPException;
import kz.gov.pki.kalkan.ocsp.OCSPReqGenerator;
import kz.gov.pki.kalkan.ocsp.OCSPResp;
import ru.ussgroup.security.trusty.exception.TrustyOCSPNotAvailableException;
import ru.ussgroup.security.trusty.exception.TrustyOCSPUnknownProblemException;
import ru.ussgroup.security.trusty.repository.TrustyRepository;

/**
 * This class is thread-safe
 */
public class KalkanOCSPRequestSender {
    private final String ocspUrl;
    
    private final TrustyRepository trustyRepository;
    
    private final static AsyncHttpClient httpClient;
    
    private final SecureRandom sr = new SecureRandom();
    
    private Inet4Address addr;
    
    static {
        if (Security.getProvider(KalkanProvider.PROVIDER_NAME) == null) Security.addProvider(new KalkanProvider());
    }
    
    static {
        AsyncHttpClientConfig cfg = new AsyncHttpClientConfig.Builder().setConnectTimeout(10_000)
                                                                       .setRequestTimeout(10_000)
                                                                       .build();
        httpClient = new AsyncHttpClient(cfg);
        
        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {
                httpClient.close();
            }
        });
    }
    
    public KalkanOCSPRequestSender(String ocspUrl, String ip, TrustyRepository trustyRepository) throws UnknownHostException {
        this.ocspUrl = ocspUrl;
        this.trustyRepository = trustyRepository;
        this.addr = (Inet4Address) Inet4Address.getByName(ip);
    }
    
    public KalkanOCSPResponse sendRequest(Set<X509Certificate> certs) {
        byte[] nonce = new byte[8];
        sr.nextBytes(nonce);
        
        try {
            List<CertificateID> ids = new ArrayList<>();
            
            for (X509Certificate cert : certs) {
                //Указываем алгоритм хэширования.
                //Принципиальной разницы для сервера нет и не зависит от алгоритма подписи сертификата
                X509Certificate issuer = trustyRepository.getIssuer(cert);
                
                if (issuer == null) {
                    throw new TrustyOCSPUnknownProblemException("Certificate issuer not found");
                }
                
                try {
                    ids.add(new CertificateID(CertificateID.HASH_SHA1, issuer, cert.getSerialNumber(), KalkanProvider.PROVIDER_NAME));
                } catch (OCSPException e) {
                    throw new TrustyOCSPUnknownProblemException(e);
                }
            }
            
            ListenableFuture<OCSPResp> f = httpClient.preparePost(ocspUrl)
                                                     .setHeader("Content-Type", "application/ocsp-request")
                                                     .setInetAddress(addr)
                                                     .setBody(getOcspPackage(ids, nonce))
                                                     .execute(new AsyncCompletionHandler<OCSPResp>() {
                                                         @Override
                                                         public OCSPResp onCompleted(Response response) throws Exception {
                                                             return new OCSPResp(response.getResponseBodyAsBytes());
                                                         }
                                                     });
            
            CompletableFuture<OCSPResp> completableFuture = new CompletableFuture<>();
            
            f.addListener(() -> {
                try {
                    completableFuture.complete(f.get());
                } catch (InterruptedException | ExecutionException e) {//Сделал двойную вложенность, для унификации обработки в синхронных методах
                    completableFuture.completeExceptionally(new RuntimeException(new TrustyOCSPNotAvailableException(e)));
                }
            }, r -> {r.run();});//Код слушателя будет выполняться либо в потоке HTTP клиента, либо в потоке, который вызывает метод addListener (если на момент вызова результат ListenableFuture уже готов)
            
            return new KalkanOCSPResponse(nonce, completableFuture);
        } catch (TrustyOCSPUnknownProblemException e) {
            CompletableFuture<OCSPResp> completableFuture = new CompletableFuture<>();
            
            completableFuture.completeExceptionally(new RuntimeException(e));
            
            return new KalkanOCSPResponse(nonce, completableFuture);
        }
    }
    
    private byte[] getOcspPackage(List<CertificateID> ids, byte[] nonce) throws TrustyOCSPUnknownProblemException {
        try {
            OCSPReqGenerator gen = new OCSPReqGenerator();
            
            for (CertificateID id : ids) {
                gen.addRequest(id);
            }
            
            gen.setRequestExtensions(generateExtensions(nonce));
            
            return gen.generate().getEncoded();
        } catch (Exception e) {
            throw new TrustyOCSPUnknownProblemException(e);
        }
    }
    
    private X509Extensions generateExtensions(byte[] nonce) {
        Hashtable<DERObjectIdentifier, X509Extension> exts = new Hashtable<>();
        
        exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, new X509Extension(false, new DEROctetString(new DEROctetString(nonce))));
        
        return new X509Extensions(exts);
    }
    
    public TrustyRepository getRepository() {
        return trustyRepository;
    }
}
