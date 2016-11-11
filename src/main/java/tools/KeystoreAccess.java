/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tools;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.security.pkcs11.SunPKCS11;
import sun.security.pkcs11.wrapper.PKCS11;

/**
 *
 * @author KTsan
 */
public final class KeystoreAccess {

    static File driver;

    public void setDriver(File driver) {
        this.driver = driver;
    }

    private void registerProvider() {
        String pkcs11Config = String.format("name=%s\nlibrary=%s",
                );
    }

    public void keystore() {
        String pkcs11Config = "name = SmartCard\nlibrary = C:\\WINDOWS\\System32\\acospkcs11.dll";
        ByteArrayInputStream configStream = new ByteArrayInputStream(pkcs11Config.getBytes());
        Provider prov = new sun.security.pkcs11.SunPKCS11(configStream);
        Security.addProvider(prov);
        KeyStore cc = null;
        char[] pin = "".toCharArray();
        try {
            cc = KeyStore.getInstance("PKCS11", prov);
            KeyStore.PasswordProtection pp = new KeyStore.PasswordProtection(pin);
            cc.load(null, pp.getPassword());
            java.util.Enumeration aliases = cc.aliases();
            while (aliases.hasMoreElements()) {
                Object alias = aliases.nextElement();
                try {
                    X509Certificate cert0 = (X509Certificate) cc.getCertificate(alias.toString());
                    System.out.println("I am: " + cert0.getSubjectDN().getName());
                } catch (Exception e) {
                    continue;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
