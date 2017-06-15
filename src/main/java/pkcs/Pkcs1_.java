/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pkcs;

import java.security.KeyStore;
import callbacks.GuiPasswordCallback;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.naming.AuthenticationException;
import lombok.Getter;
import lombok.extern.java.Log;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
@Log
public abstract class Pkcs1_ {

    @Getter
    protected GuiPasswordCallback _guiPasswordCallback;
    //protected KeyStore.Builder _builder;
    @Getter
    protected KeyStore _certKeyStore;
    protected KeyStore.CallbackHandlerProtection _chp;
    @Getter
    protected Provider _provider;

    public void initGuiHandler(GuiPasswordCallback guiPasswordCallback) {
        _guiPasswordCallback = guiPasswordCallback;
    }

    public abstract List<String> listAliases() throws KeyStoreException;

    public abstract X509Certificate getCertificate(String alias) throws KeyStoreException;

    public abstract void login() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, AuthenticationException;
}
