/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package exceptions;

/**
 * This exception must be thrown when a verification problem occurs.
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 * @author Svetlin Nakov
 */
public class CertificateVerificationException extends Exception {

    private static final long serialVersionUID = 1L;

    public CertificateVerificationException(String message, Throwable cause) {
        super(message, cause);
    }

    public CertificateVerificationException(String message) {
        super(message);
    }
}
