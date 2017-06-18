/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package exceptions;

/**
 * Thrown when timestamping cannot be performed.
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public class TimestampingException extends Exception {

    private static final long serialVersionUID = 1L;

    public TimestampingException(String message, Throwable cause) {
        super(message, cause);
    }

    public TimestampingException(String message) {
        super(message);
    }
}
