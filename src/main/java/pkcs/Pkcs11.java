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
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.AuthenticationException;
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
    public final void login() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, AuthenticationException {
        char[] pin = _guiPasswordCallback.getPassword();
        if (pin != null) {
            _certKeyStore = KeyStore.getInstance("PKCS11", _provider);
            _certKeyStore.load(null, pin);
        } else {
            throw new AuthenticationException("No pin input.");
        }
    }

    public String getSlotDescription() {
        return slotDescription;
    }

    public X509Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        return (X509Certificate[]) _certKeyStore.getCertificateChain(alias);
    }

    public String getCertificateAlias(Certificate cert) throws KeyStoreException {
        return _certKeyStore.getCertificateAlias(cert);
    }

    public List<X509Certificate> listCertificates() throws KeyStoreException {
        List<X509Certificate> list = new ArrayList<>();
        java.util.Enumeration aliases = _certKeyStore.aliases();
        while (aliases.hasMoreElements()) {
            Object alias = aliases.nextElement();
            System.out.println(alias);
            X509Certificate cert0 = (X509Certificate) _certKeyStore.getCertificate(alias.toString());
            list.add(cert0);
        }
        return list;
    }

    @Override
    public List<String> listAliases() throws KeyStoreException {
        return Collections.list(_certKeyStore.aliases());

    }

    @Override
    public X509Certificate getCertificate(String alias) throws KeyStoreException {
        return (X509Certificate) _certKeyStore.getCertificate(alias);
    }
}
