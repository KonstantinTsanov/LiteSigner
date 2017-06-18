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
 * Contract between the certificate panel on the GUI and the back-end.
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public interface CertificatePanel {

    /**
     * Gets the certificate table model.
     *
     * @return Table model holding the certificates for the selected token.
     */
    public DefaultTableModel getTableModel();

    /**
     * Gets the panel's parent frame.
     *
     * @return The parent JFrame.
     */
    public JFrame getPanelParent();

    /**
     * Gets the JTable in which the certificates are displayed.
     *
     * @return The table showing the certificates for the selected token.
     */
    public JTable getCertificateTable();
}
