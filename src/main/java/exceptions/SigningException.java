/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package exceptions;

/**
 * This exception must be thrown whenever any problems with the signing process
 * occur.
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public class SigningException extends Exception {

    private static final long serialVersionUID = 1L;

    public SigningException(String message, Throwable cause) {
        super(message, cause);
    }

    public SigningException(String message) {
        super(message);
    }
}
