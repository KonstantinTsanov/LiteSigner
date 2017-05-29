/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package guihandler;

import callbacks.GuiPasswordCallback;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.logging.Level;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.swing.SwingUtilities;
import lombok.extern.java.Log;

/**
 * Used to ask the user to input PIN 
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
@Log
public class GuiHandler implements CallbackHandler {

    private GuiPasswordCallback _guiPasswordCallback;

    public void setGuiPasswordCallback(GuiPasswordCallback guiPasswordCallback) {
        _guiPasswordCallback = guiPasswordCallback;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof PasswordCallback) {
                try {
                    FutureTask<char[]> acquirePasswordFromSwing = new FutureTask<>(_guiPasswordCallback::getPassword);
                    PasswordCallback passwordCallback = (PasswordCallback) callback;
                    SwingUtilities.invokeAndWait(acquirePasswordFromSwing);
                    passwordCallback.setPassword(acquirePasswordFromSwing.get());
                } catch (InterruptedException ex) {
                    log.log(Level.SEVERE, "The process to obtain PIN has been interrupted!", ex);
                } catch (InvocationTargetException ex) {
                    log.log(Level.SEVERE, "Another problem occured while invoking the method/waiting for the method used to obtain PIN.", ex);
                } catch (ExecutionException ex) {
                    log.log(Level.SEVERE, "There was a problem while obtaining the PIN.", ex);
                }
            }
        }
    }
}
