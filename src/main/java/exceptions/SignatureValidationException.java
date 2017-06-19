/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package exceptions;

/**
 * Should be thrown whenever validation fails.
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public class SignatureValidationException extends Exception {

    private static final long serialVersionUID = 1L;

    public SignatureValidationException(String message, Throwable cause) {
        super(message, cause);
    }

    public SignatureValidationException(String message) {
        super(message);
    }
}
