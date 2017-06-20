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

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public class TrustStoreImporter {

    public static void createStore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        char[] password = "secured".toCharArray();
        ks.load(null, password);

        try (FileOutputStream fos = new FileOutputStream("src/main/resources/keystore/Keystore.jks")) {
            ks.store(fos, password);
        }
    }

    public static void importToStore() throws FileNotFoundException, IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException {
        String certfile = "src/main/resources/keystore/1.cer";
        String certfile1 = "src/main/resources/keystore/2.cer";
        FileInputStream is = new FileInputStream("src/main/resources/keystore/Keystore.jks");

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, "secured".toCharArray());

        String alias = "intermediate";
        String alias1 = "CA";
        char[] password = "secured".toCharArray();

//////
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream certstream = fullStream(certfile);
        InputStream certstream1 = fullStream(certfile1);
        Certificate certs = cf.generateCertificate(certstream);
        Certificate certs1 = cf.generateCertificate(certstream1);

///
        File keystoreFile = new File("src/main/resources/keystore/Keystore.jks");
// Load the keystore contents
        FileInputStream in = new FileInputStream(keystoreFile);
        keystore.load(in, password);
        in.close();

// Add the certificate
        keystore.setCertificateEntry(alias, certs);
        keystore.setCertificateEntry(alias1, certs1);
// Save the new keystore contents
        FileOutputStream out = new FileOutputStream(keystoreFile);
        keystore.store(out, password);
        out.close();

    }

    private static InputStream fullStream(String fname) throws IOException {
        FileInputStream fis = new FileInputStream(fname);
        DataInputStream dis = new DataInputStream(fis);
        byte[] bytes = new byte[dis.available()];
        dis.readFully(bytes);
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        return bais;
    }

    private static void ReadContent() {
        InputStream is = null;
        try {

            File file = new File("src/main/resources/keystore/Keystore.jks");
            is = new FileInputStream(file);
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            String password = "secured";
            keystore.load(is, password.toCharArray());
            //TODO

        } catch (java.security.cert.CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (null != is) {
                try {
                    is.close();
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        }
    }

    public static void main(String args[]) {
        try {
            createStore();
            importToStore();
            ReadContent();
        } catch (KeyStoreException ex) {
            Logger.getLogger(TrustStoreImporter.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(TrustStoreImporter.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(TrustStoreImporter.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(TrustStoreImporter.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
