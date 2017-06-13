/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pkcs;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.login.LoginException;
import lombok.extern.java.Log;
import sun.security.pkcs11.SunPKCS11;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
@Log
public class Pkcs11 extends Pkcs1_ {
    
    private final File _driver;
    private final long _slotId;
    private final String slotDescription;
    
    private static int pluggedCount = 0;

    /**
     * Creates new Pkcs11 instance using specified slotId and driver.
     *
     * @param slotDescription Description of the slot.
     * @param slotId The id of the slot in which the device has been plugged in.
     * @param driver Driver to be used with the slot.
     */
    public Pkcs11(String slotDescription, long slotId, File driver) {
        Objects.requireNonNull(driver, "Driver must not be null!");
        this.slotDescription = slotDescription;
        _driver = driver;
        _slotId = slotId;
        registerProvider();
    }
    
    private void registerProvider() {
        String pkcs11Config = String.format("name=%s\nlibrary=%s\nslotListIndex=%d", "SmartCard" + pluggedCount++, _driver, _slotId);
        ByteArrayInputStream configStream = new ByteArrayInputStream(pkcs11Config.getBytes());
        _provider = new sun.security.pkcs11.SunPKCS11(configStream);
        Security.addProvider(_provider);
    }
    
    public void closeSession() {
        try {
            ((SunPKCS11) _provider).logout();
        } catch (LoginException ex) {
            Logger.getLogger(Pkcs11.class.getName()).log(Level.SEVERE, null, ex);
        }
        Security.removeProvider(_provider.getName());
        _provider.clear();
        _provider = null;
        pluggedCount--;
    }
    
    @Override
    public final void login() throws KeyStoreException {
        _chp = new KeyStore.CallbackHandlerProtection(_guiHandler);
        _builder = KeyStore.Builder.newInstance("PKCS11", _provider, _chp);
        try {
            _certKeyStore = _builder.getKeyStore();
        } catch (KeyStoreException ex) {
            log.log(Level.SEVERE, "Error occured during login!", ex);
            throw ex;
        }
    }
    
    public String getSlotDescription() {
        return slotDescription;
    }
    
    public Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        return _certKeyStore.getCertificateChain(alias);
    }
    
    public String getCertificateAlias(Certificate cert) throws KeyStoreException {
        return _certKeyStore.getCertificateAlias(cert);
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
