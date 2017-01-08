/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pkcs;

import callbacks.PasswordCallback;
import java.security.KeyStore;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
abstract class Pkcs1_ {

    protected PasswordCallback _passwordCallback;

    private KeyStore _certKeyStore;

    public void setPasswordSource(PasswordCallback passwordCallback) {
        _passwordCallback = passwordCallback;
    }

    protected abstract void login();
}
