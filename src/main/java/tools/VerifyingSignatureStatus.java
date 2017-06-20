/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tools;

/**
 * Stores information about the signature verification process.
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public class VerifyingSignatureStatus {

    private String status;

    /**
     * Includes additional information to the status string.
     *
     * @param information Status information to be included.
     */
    public void includeStatus(String information) {
        if (status.length() != 0) {
            status = status.concat("\n".concat(information));
        } else {
            status = information;
        }
    }

    /**
     * Returns the status string.
     *
     * @return - the status string.
     */
    public String getStatus() {
        return status;
    }
}
