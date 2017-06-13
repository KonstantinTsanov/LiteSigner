/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package callbacks;

import javax.swing.DefaultListModel;
import javax.swing.JFrame;
import javax.swing.JList;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

/**
 * Contract between the window for device selection and the back-end
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public interface DevicePanel {

    /**
     * Gets the model which lists the devices and their description on the GUI.
     *
     * @return Model containing list of token descriptions.
     */
    public DefaultTableModel getTokensModel();

    /**
     * Gets the parent in which the panel is placed.
     *
     * @return The parent
     */
    public JFrame getPanelParent();

    public JTable getTokensTable();

}
