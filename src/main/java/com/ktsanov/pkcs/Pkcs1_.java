/* 
 * The MIT License
 *
 * Copyright 2017 Konstantin Tsanov <k.tsanov@gmail.com>.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.ktsanov.pkcs;

import java.security.KeyStore;
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
import com.ktsanov.callbacks.PasswordCallback;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
@Log
public abstract class Pkcs1_ {

    @Getter
    protected PasswordCallback _passwordCallback;
    //protected KeyStore.Builder _builder;
    @Getter
    protected KeyStore _certKeyStore;
    protected KeyStore.CallbackHandlerProtection _chp;
    @Getter
    protected Provider _provider;

    public void initGuiHandler(PasswordCallback guiPasswordCallback) {
        _passwordCallback = guiPasswordCallback;
    }

    public abstract List<String> listAliases() throws KeyStoreException;

    public abstract X509Certificate getCertificate(String alias) throws 
            KeyStoreException;

    public abstract void login() throws KeyStoreException, 
            IOException, NoSuchAlgorithmException, 
            CertificateException, AuthenticationException;
}
