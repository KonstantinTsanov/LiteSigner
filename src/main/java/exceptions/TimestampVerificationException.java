/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package exceptions;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public class TimestampVerificationException extends Exception {

    private static final long serialVersionUID = 1L;

    public TimestampVerificationException(String message, Throwable cause) {
        super(message, cause);
    }

    public TimestampVerificationException(String message) {
        super(message);
    }
}
