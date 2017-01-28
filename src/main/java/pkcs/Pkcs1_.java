/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pkcs;

import java.security.KeyStore;
import callbacks.GuiPasswordCallback;
import guihandler.GuiHandler;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import lombok.Getter;
import lombok.extern.java.Log;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
@Log
public abstract class Pkcs1_ {

    @Getter
    protected GuiHandler _guiHandler;
    protected KeyStore.Builder _builder;
    @Getter
    protected KeyStore _certKeyStore;
    protected KeyStore.CallbackHandlerProtection _chp;
    @Getter
    protected Provider _provider;

    public void initGuiHandler(GuiPasswordCallback guiPasswordCallback) {
        _guiHandler = new GuiHandler();
        _guiHandler.setGuiPasswordCallback(guiPasswordCallback);
    }

    public abstract List<String> listAliases();

    public abstract X509Certificate getCertificate(String alias);

    public abstract void login();
}
