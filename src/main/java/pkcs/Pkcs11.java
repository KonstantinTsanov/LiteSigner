/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pkcs;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public class Pkcs11 {

    private static File _driver;

    private static Provider _provider;

    public static void setDriver(File driver) {
        Objects.requireNonNull(driver, "Driver must not be null!");
        _driver = driver;
    }

    private void registerProvider() {
        Objects.requireNonNull(_driver, "Driver must not be null!");
        String pkcs11Config = String.format("name=%s\nlibrary=%s", "SmartCardUtil", _driver);
        //String pkcs11Config = "name = SmartCardUtil\nlibrary = C:\\WINDOWS\\System32\\acospkcs11.dll";
        ByteArrayInputStream configStream = new ByteArrayInputStream(pkcs11Config.getBytes());
        _provider = new sun.security.pkcs11.SunPKCS11(configStream);
        Security.addProvider(_provider);
    }

    public List<X509Certificate> listCertificates() {
        registerProvider();
        KeyStore cc = null;
        List<X509Certificate> list = new ArrayList<>();
        char[] pin = "".toCharArray();
        try {
            cc = KeyStore.getInstance("PKCS11", _provider);
            KeyStore.PasswordProtection pp = new KeyStore.PasswordProtection(pin);
            cc.load(null, pp.getPassword());
            java.util.Enumeration aliases = cc.aliases();
            while (aliases.hasMoreElements()) {
                Object alias = aliases.nextElement();
                try {
                    X509Certificate cert0 = (X509Certificate) cc.getCertificate(alias.toString());
                    list.add(cert0);
                } catch (Exception e) {
                    continue;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return list;
    }
}
