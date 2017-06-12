/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package callbacks;

import javax.swing.JFrame;
import javax.swing.table.DefaultTableModel;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public interface CertificatePanel {

    /**
     * Gets the table model for the panel
     *
     * @return Table model showing the certificates for the selected token
     */
    public DefaultTableModel getTableModel();

    /**
     * Gets the parent in which the panel is placed.
     *
     * @return The parent
     */
    public JFrame getPanelParent();
}
