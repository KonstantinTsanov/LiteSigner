/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package callbacks;

import javax.swing.JFrame;
import javax.swing.JTextArea;

/**
 * Contract between the signature verification panel and the back-end.
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public interface SignatureVerificationPanel {

    /**
     * Gets the text area in which the validation details are displayed.
     *
     * @return Validation details output textarea.
     */
    public JTextArea getSignatureDetailsJTextArea();

    /**
     * Gets the panel's parent frame.
     *
     * @return JFrame parent.
     */
    public JFrame getPanelParent();
}
