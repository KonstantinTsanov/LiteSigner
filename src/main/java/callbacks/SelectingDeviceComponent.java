/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package callbacks;

import javax.swing.DefaultListModel;
import javax.swing.JFrame;
import javax.swing.JList;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public interface SelectingDeviceComponent {

    public DefaultListModel<String> getTokensModel();

    public JFrame getParent();

}
