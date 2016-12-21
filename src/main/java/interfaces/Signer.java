/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package interfaces;

import java.io.InputStream;
import java.io.OutputStream;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public interface Signer {

    public void Sign(InputStream input, OutputStream output);

    public void Verify(InputStream signedData, InputStream dataToVerify);
}
