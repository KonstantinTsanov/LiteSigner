/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package callbacks;

import javax.swing.JFrame;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

/**
 * Contract between the device selection panel and the back-end.
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public interface DevicePanel {

    /**
     * Gets the device table model.
     *
     * @return Model containing list of token descriptions.
     */
    public DefaultTableModel getTokensModel();

    /**
     * Gets panel's parent frame.
     *
     * @return The parent
     */
    public JFrame getPanelParent();

    /**
     * Gets the JTable in which the devices are displayed.
     *
     * @return The table showing the currently attached devices.
     */
    public JTable getTokensTable();

}
