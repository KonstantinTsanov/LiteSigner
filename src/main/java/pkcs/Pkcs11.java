/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pkcs;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import lombok.extern.java.Log;
import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_INFO;
import sun.security.pkcs11.wrapper.CK_SLOT_INFO;
import sun.security.pkcs11.wrapper.CK_TOKEN_INFO;
import sun.security.pkcs11.wrapper.PKCS11Constants;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKA_ID;
import static sun.security.pkcs11.wrapper.PKCS11Constants.CKA_LABEL;
import sun.security.pkcs11.wrapper.PKCS11Exception;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
@Log
public class Pkcs11 extends Pkcs1_ {

    private final File _driver;


    public Pkcs11(File driver) {
        Objects.requireNonNull(driver, "Driver must not be null!");
        _driver = driver;
        registerProvider();
    }

    private void registerProvider() {
        String pkcs11Config = String.format("name=%s\nlibrary=%s", "SmartCard" + Thread.currentThread().getId(), _driver);
        //String pkcs11Config = "name = SmartCardUtil\nlibrary = C:\\WINDOWS\\System32\\acospkcs11.dll";
        ByteArrayInputStream configStream = new ByteArrayInputStream(pkcs11Config.getBytes());
        _provider = new sun.security.pkcs11.SunPKCS11(configStream);
        Security.addProvider(_provider);
    }

    private void unregisterProvider() {
        Security.removeProvider(_provider.getName());
    }

    @Override
    public final void login() {
        _chp = new KeyStore.CallbackHandlerProtection(_guiHandler);
        _builder = KeyStore.Builder.newInstance("PKCS11", _provider, _chp);
        try {
            _certKeyStore = _builder.getKeyStore();
        } catch (KeyStoreException ex) {
            log.log(Level.SEVERE, "Error occured during operation!", ex);
            throw new RuntimeException(ex);
        }
    }

    public List<X509Certificate> listCertificates() {
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

    @Override
    public List<String> listAliases() {
        try {
            return Collections.list(_certKeyStore.aliases());
        } catch (KeyStoreException ex) {
            log.log(Level.SEVERE, "The keystore has not been loaded!", ex);
            throw new RuntimeException("Keystore not loaded!", ex);
        }
    }

    @Override
    public X509Certificate getCertificate(String alias) {
        try {
            return (X509Certificate) _certKeyStore.getCertificate(alias);
        } catch (KeyStoreException ex) {
            log.log(Level.SEVERE, "The keystore has not been loaded!", ex);
            throw new RuntimeException("Keystore not loaded!", ex);
        }
    }
}
