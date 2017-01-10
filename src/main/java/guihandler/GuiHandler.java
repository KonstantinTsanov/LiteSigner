/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package guihandler;

import callbacks.GuiPasswordCallback;
import java.io.IOException;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public class GuiHandler implements CallbackHandler {

    private GuiPasswordCallback _guiPasswordCallback;

    public void setGuiPasswordCallback(GuiPasswordCallback guiPasswordCallback) {
        _guiPasswordCallback = guiPasswordCallback;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
                PasswordCallback passwordCallback = (PasswordCallback) callback;
                passwordCallback.setPassword(_guiPasswordCallback.getPassword());
            }
        }
    }
}
