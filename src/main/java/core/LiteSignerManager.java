/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package core;

import callbacks.CertificatePanel;
import callbacks.GuiPasswordCallback;
import java.io.File;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import lombok.extern.java.Log;
import pkcs.Pkcs11;
import sun.security.pkcs11.wrapper.PKCS11Exception;
import tools.DeviceManager;
import org.apache.commons.lang3.exception.ExceptionUtils;
import java.util.Locale;
import java.util.ResourceBundle;
import callbacks.DevicePanel;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Objects;
import java.util.Vector;
import java.util.logging.Logger;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

/**
 * Manages all Pkcs11 instances
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
@Log
public class LiteSignerManager {

    private final ExecutorService logInExec = Executors.newFixedThreadPool(1);
    private final ExecutorService certificateDisplayExec = Executors.newFixedThreadPool(1);
    private final ScheduledExecutorService deviceScanner = Executors.newSingleThreadScheduledExecutor();
    private final List<Pkcs11> pkcs11Instances = new ArrayList<>();

    private static final LiteSignerManager singleton = new LiteSignerManager();

    private DevicePanel devicePanel;
    private CertificatePanel certificatePanel;

    private Locale currentLocale;
    private GuiPasswordCallback passwordCallback;
    private final String authenticated = "Logged in";
    private final String unauthenticated = "Unauthenticated";
    //Must be able to control both description and the entry containing slotIndex and driver
    Map<String, Map.Entry<Integer, File>> slotList = new HashMap<>();

    /**
     * Must be called before executing other methods in the class.
     *
     * @param devicePanel The implementation of the GuiPasswordCallback
     * interface.
     * @param certificatePanel
     * @param passwordCallback
     */
    public void setComponents(DevicePanel devicePanel, CertificatePanel certificatePanel, GuiPasswordCallback passwordCallback) {
        this.devicePanel = devicePanel;
        this.certificatePanel = certificatePanel;
        this.passwordCallback = passwordCallback;
    }

    private LiteSignerManager() {

    }

    public static LiteSignerManager getInstance() {
        return singleton;
    }

    public void setLocale(Locale locale) {
        this.currentLocale = locale;
    }

    public void deviceLogIn(String slotDescription) {
        Objects.requireNonNull(slotDescription);
        logInExec.submit(() -> {
            if (getInstanceIfExists(slotDescription) == null) {
                Entry<Integer, File> selectedSlot = slotList.get(slotDescription);
                Pkcs11 smartcard = new Pkcs11(slotDescription, selectedSlot.getKey(), selectedSlot.getValue());
                smartcard.initGuiHandler(passwordCallback);
                try {
                    smartcard.login();
                    if (devicePanel.getTokensTable().getSelectedRow() != -1
                            && slotDescription.equals(devicePanel.getTokensTable().getValueAt(devicePanel.getTokensTable().getSelectedRow(), 0))) {
                        printCertificates(smartcard);
                    }
                    pkcs11Instances.add(smartcard);
                    SwingUtilities.invokeLater(() -> {
                        DefaultTableModel model = devicePanel.getTokensModel();
                        model.setValueAt(authenticated, getRowByValue(model, slotDescription), 1);
                    });
                    //TODO FIX
//
                } catch (KeyStoreException ex) {
                    smartcard.closeSession();
                    ResourceBundle r = ResourceBundle.getBundle("CoreBundle", currentLocale);
                    if ("CKR_PIN_INCORRECT".equals(ExceptionUtils.getRootCause(ex).getLocalizedMessage())) {
                        SwingUtilities.invokeLater(() -> {
                            JOptionPane.showMessageDialog(devicePanel.getPanelParent(), r.getString("LiteSignerManager.incorrectPin"),
                                    r.getString("LiteSignerManager.dialogMessage"), JOptionPane.WARNING_MESSAGE);
                        });
                    } else if ("CKR_PIN_LOCKED".equals(ExceptionUtils.getRootCause(ex).getLocalizedMessage())) {
                        SwingUtilities.invokeLater(() -> {
                            JOptionPane.showMessageDialog(devicePanel.getPanelParent(), r.getString("LiteSignerManager.pinLocked"),
                                    r.getString("LiteSignerManager.dialogMessage"), JOptionPane.WARNING_MESSAGE);
                        });
                    } else {
                        SwingUtilities.invokeLater(() -> {
                            //TODO use bundle
                            JOptionPane.showMessageDialog(devicePanel.getPanelParent(), "There is a problem with the device.",
                                    r.getString("LiteSignerManager.dialogMessage"), JOptionPane.WARNING_MESSAGE);
                        });
                    }
                } catch (CertificateEncodingException ex) {
                    //TODO
                    Logger.getLogger(LiteSignerManager.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });
    }

    /**
     * Runs the device scanner.
     *
     * @param n seconds between subsequent calls to the scanning thread.
     */
    public void runDeviceScanner(int n) {
        Thread t = new Thread() {
            @Override
            public void run() {
                try {
                    Map<String, Map.Entry<Integer, File>> freshDeviceList = DeviceManager.getInstance().scanForUSBDevices();
                    if (freshDeviceList != null) {
                        for (Iterator<Pkcs11> it = pkcs11Instances.iterator(); it.hasNext();) {
                            String slotDescription = it.next().getSlotDescription();
                            if (slotList.containsKey(slotDescription) == false) {
                                it.remove();
                            }
                        }
                        //todo
                        SwingUtilities.invokeLater(() -> {
                            freshDeviceList.forEach((description, indexAndDriver) -> {
                                if (slotList.containsKey(description) == false) {
                                    slotList.put(description, indexAndDriver);
                                    devicePanel.getTokensModel().addRow(new Object[]{description, unauthenticated});
                                }
                            });
                            for (Iterator<Map.Entry<String, Map.Entry<Integer, File>>> it = slotList.entrySet().iterator(); it.hasNext();) {
                                String description = it.next().getKey();
                                if (freshDeviceList.containsKey(description) == false) {
                                    it.remove();
                                    int row = getRowByValue(devicePanel.getTokensModel(), description);
                                    if (devicePanel.getTokensTable().getSelectedRow() == row) {
                                        devicePanel.getTokensTable().clearSelection();
                                    }
                                    devicePanel.getTokensModel().removeRow(row);
                                    if (devicePanel.getTokensTable().getRowCount() != 0) {
                                        if (row < devicePanel.getTokensTable().getRowCount()) {
                                            devicePanel.getTokensTable().changeSelection(row, 0, false, false);
                                        } else if (row == devicePanel.getTokensTable().getRowCount()) {
                                            devicePanel.getTokensTable().changeSelection(row - 1, 0, false, false);
                                        }
                                    }
                                }
                            }
                        });
                    }
                } catch (PKCS11Exception ex) {
                    SwingUtilities.invokeLater(() -> {
                        JOptionPane.showMessageDialog(devicePanel.getPanelParent(), "There is a problem with the device.");
                    });
                }

            }
        };
        deviceScanner.scheduleAtFixedRate(t, 0, n, TimeUnit.SECONDS);
        t.start();
    }

    public void displayCertificates(String slotDescription) {
        certificateDisplayExec.submit(() -> {
            Pkcs11 smartcard = getInstanceIfExists(slotDescription);
            if (smartcard != null) {
                try {
                    printCertificates(smartcard);
                } catch (CertificateEncodingException ex) {
                    SwingUtilities.invokeLater(() -> {
                        JOptionPane.showMessageDialog(devicePanel.getPanelParent(), "Error occured while reading certificate!");
                    });
                } catch (KeyStoreException ex) {
                    SwingUtilities.invokeLater(() -> {
                        JOptionPane.showMessageDialog(devicePanel.getPanelParent(), "Error occured while reading certificate!");
                    });
                }
            }
        });
    }

    private void printCertificates(Pkcs11 smartcard) throws CertificateEncodingException, KeyStoreException {
        for (X509Certificate certificate : smartcard.listCertificates()) {
            Vector row = new Vector();

            X500Name subject = new JcaX509CertificateHolder(certificate).getSubject();
            RDN cn = subject.getRDNs(BCStyle.CN)[0];
            String subjectCN = IETFUtils.valueToString(cn.getFirst().getValue());
            row.add(subjectCN);

            X500Name publisher = new JcaX509CertificateHolder(certificate).getIssuer();
            RDN cn1 = publisher.getRDNs(BCStyle.CN)[0];
            String issuerCN = IETFUtils.valueToString(cn1.getFirst().getValue());
            row.add(issuerCN);

            SimpleDateFormat formatter = new SimpleDateFormat("dd-MM-yyyy kk:mm z");
            Date date = certificate.getNotBefore();
            String format = formatter.format(date);
            row.add(format);
            certificatePanel.getTableModel().addRow(row);
        }
    }

    public void clearCertificateList() {
        certificatePanel.getTableModel().setRowCount(0);
    }

    /**
     * Descriptions are always located on the first column
     *
     * @param model
     * @param value
     * @return
     */
    private int getRowByValue(TableModel model, Object value) {
        for (int i = model.getRowCount() - 1; i >= 0; --i) {
            if (model.getValueAt(i, 0).equals(value)) {
                return i;
            }
        }
        return -1;
    }

    private Pkcs11 getInstanceIfExists(String slotDescription) {
        for (Pkcs11 instance : pkcs11Instances) {
            if (instance.getSlotDescription().equals(slotDescription)) {
                return instance;
            }
        }
        return null;
    }

    public void cancelDeviceScanner() {
        deviceScanner.shutdown();
        try {
            deviceScanner.awaitTermination(3, TimeUnit.SECONDS);
        } catch (InterruptedException ex) {
            log.log(Level.SEVERE, "Failed to clean things up before closing the application!", ex);
        }
    }

}
