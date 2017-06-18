/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package callbacks;

/**
 * Obtains the PIN from the user when necessary.
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public interface PasswordCallback {

    /**
     * Gets the pin from the user.
     *
     * @return PIN.
     */
    public char[] getPin();
}
