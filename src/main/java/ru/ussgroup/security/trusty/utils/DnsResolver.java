package ru.ussgroup.security.trusty.utils;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DnsResolver {
    private static final Logger logger = LoggerFactory.getLogger(DnsResolver.class);
    
    private static ConcurrentHashMap<String, InetAddress> m = new ConcurrentHashMap<>();

    static {
        Thread t = new Thread () {
            @Override
            public void run() {
                while (!interrupted()) {
                    for (String domainName : m.keySet()) {
                        try {
                            m.put(domainName, InetAddress.getByName(new URI(domainName).getHost()));
                        } catch (Exception e) {
                            logger.debug("", e);
                        }
                    }
                    
                    try {
                        Thread.sleep(10_000);
                    } catch (InterruptedException e) {
                        interrupt();
                    }
                }
            }
        };
        
        t.setDaemon(true);
        t.start();
    }

    public static synchronized void addDomainName(String domainName) {
        if (m.get(domainName) == null) {
            try {
                m.put(domainName, InetAddress.getByName(new URI(domainName).getHost()));
            } catch (UnknownHostException | URISyntaxException e) {
                throw new RuntimeException(e);
            }
        }
    }
    
    public static InetAddress getInetAddress(String domainName) {
        return m.get(domainName);
    }
}