/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package callbacks.impl;

import callbacks.PasswordCallback;
import java.awt.Component;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.event.AncestorEvent;
import javax.swing.event.AncestorListener;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public class PasswordJOptionPane extends JOptionPane implements PasswordCallback {

    private final Component parent;

    public PasswordJOptionPane(Component component) {
        parent = component;
    }

    @Override
    public char[] getPassword() {
        String messageTitle = "Enter PIN";
        JPasswordField password = new JPasswordField();
        password.addAncestorListener(new AncestorListener() {
            @Override
            public void ancestorRemoved(final AncestorEvent event) {
            }

            @Override
            public void ancestorMoved(final AncestorEvent event) {
            }

            @Override
            public void ancestorAdded(final AncestorEvent event) {
                password.requestFocusInWindow();
            }
        });

        Object[] objs = {"Enter password:", password};
        int result = JOptionPane.showConfirmDialog(parent, objs, messageTitle, JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE, null);

        while (result == JOptionPane.OK_OPTION && password.getPassword().length == 0) {
            JOptionPane.showMessageDialog(parent, "Please enter a valid password.", "Password is not valid",
                    JOptionPane.ERROR_MESSAGE, null);
            result = 0;
            result = JOptionPane.showConfirmDialog(parent, objs, messageTitle, JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.PLAIN_MESSAGE, null);
        }
        return password.getPassword();
    }
}
