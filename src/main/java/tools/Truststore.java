/* 
 * The MIT License
 *
 * Copyright 2017 Konstantin Tsanov <k.tsanov@gmail.com>.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
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
