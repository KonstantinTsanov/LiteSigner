/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pkcs;

import enums.KeyStoreType;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import lombok.extern.java.Log;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
@Log
public class Pkcs11 extends Pkcs1_ {

    private File _driver;

    private Provider _provider;

    private KeyStore _certKeyStore;

    public void setDriver(File driver) {
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

    private void unregisterProvider() {
        Security.removeProvider(_provider.getName());
    }

    @Override
    protected final void login() {
        char[] pin = _passwordCallback.getPassword();
        try {
            _certKeyStore = KeyStore.getInstance(KeyStoreType.PKCS11.name(), _provider);
        } catch (KeyStoreException ex) {
            log.log(Level.SEVERE, null, ex);
            throw new RuntimeException(ex);
        }
        KeyStore.PasswordProtection pp = new KeyStore.PasswordProtection(pin);
        try {
            _certKeyStore.load(null, pp.getPassword());
        } catch (IOException ex) {
            log.log(Level.SEVERE, "An error occured", ex);
            throw new RuntimeException(ex);
        } catch (NoSuchAlgorithmException ex) {
            log.log(Level.SEVERE, "An error occured while loading device!", ex);
            throw new RuntimeException(ex);
        } catch (CertificateException ex) {
            log.log(Level.SEVERE, null, ex);
            throw new RuntimeException(ex);
        }

    }

    public List<X509Certificate> listCertificates() {
        registerProvider();
        List<X509Certificate> list = new ArrayList<>();
        try {
            java.util.Enumeration aliases = _certKeyStore.aliases();
            while (aliases.hasMoreElements()) {
                Object alias = aliases.nextElement();
                try {
                    X509Certificate cert0 = (X509Certificate) _certKeyStore.getCertificate(alias.toString());
                    list.add(cert0);
                } catch (KeyStoreException e) {
                    log.log(Level.SEVERE, "There's a problem with your keystore!");
                    throw new RuntimeException("Keystore exception! ", e);
                }
            }
        } catch (Exception e) {
            //TODO
            log.log(Level.SEVERE, "There's a problem!");
            throw new RuntimeException("Keystore! ", e);
        }
        return list;
    }

    public List<String> listAliases() {
        //TODO
        return null;
    }
}
