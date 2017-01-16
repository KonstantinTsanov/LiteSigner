/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package signers;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.Certificate;
import java.util.Objects;

/**
 *
 * @author KTsan
 */
public class Pkcs7 {

    private InputStream input;
    private OutputStream output;
    private Certificate certificate;
    private boolean attached = false;

    public void sign() {
        Objects.requireNonNull(input);
        Objects.requireNonNull(output);
        Objects.requireNonNull(certificate);
        
    }
}
