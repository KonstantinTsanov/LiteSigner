/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pkcs;

import java.security.KeyStore;
import callbacks.GuiPasswordCallback;
import guihandler.GuiHandler;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
abstract class Pkcs1_ {

    protected KeyStore _certKeyStore;
    protected KeyStore.Builder _builder;
    protected KeyStore.CallbackHandlerProtection _chp;
    protected GuiHandler _guiHandler;

    public void initGuiHandler(GuiPasswordCallback guiPasswordCallback) {
        _guiHandler = new GuiHandler();
        _guiHandler.setGuiPasswordCallback(guiPasswordCallback);
    }

    protected abstract void login();
}
