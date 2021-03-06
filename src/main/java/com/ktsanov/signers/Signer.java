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
package com.ktsanov.signers;

import com.ktsanov.exceptions.CertificateVerificationException;
import com.ktsanov.exceptions.SignatureValidationException;
import com.ktsanov.exceptions.SigningException;
import com.ktsanov.exceptions.TimestampVerificationException;
import com.ktsanov.exceptions.TimestampingException;
import java.io.File;
import java.io.IOException;
import javax.naming.AuthenticationException;
import com.ktsanov.pkcs.Pkcs1_;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public abstract class Signer {

    protected Pkcs1_ _pkcs1x;

    public abstract void sign(boolean attached) throws AuthenticationException, SigningException, TimestampingException;

    public abstract String validate(File signatureOrAttached, File signedFile) throws IOException, SignatureValidationException,
            TimestampVerificationException, CertificateVerificationException;
}
