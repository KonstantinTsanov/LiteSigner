/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tools;

import exceptions.CertificateVerificationException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public class Truststore {

    private static Truststore singleton = new Truststore();

    public static Truststore getInstance() {
        return singleton;
    }

    public List<X509Certificate> ReadContent() throws CertificateVerificationException {
        try (InputStream is = getClass().getResourceAsStream("/keystore/Keystore.jks")) {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            String password = "secured";
            keystore.load(is, password.toCharArray());
            ArrayList<X509Certificate> certs = new ArrayList<>();
            Enumeration enumeration = keystore.aliases();
            while (enumeration.hasMoreElements()) {
                String alias = (String) enumeration.nextElement();
                X509Certificate certificate = (X509Certificate) keystore.getCertificate(alias);
                certs.add(certificate);
            }
            return certs;
        } catch (Exception ex) {
            throw new CertificateVerificationException("Cannot get the trusted certificates from keystore!", ex);
        }
    }
}
