/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package signers;

import exceptions.CertificateVerificationException;
import exceptions.SignatureValidationException;
import java.io.File;
import java.io.IOException;
import pkcs.Pkcs1_;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public abstract class Signer {

    protected Pkcs1_ _pkcs1x;

    public abstract void sign(boolean attached);

    public abstract String validate(File signatureOrAttached, File signedFile) throws IOException, SignatureValidationException;
}
