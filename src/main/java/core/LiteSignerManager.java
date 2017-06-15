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
import exceptions.CertificateVerificationException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.AbstractMap.SimpleEntry;
import java.util.Date;
import java.util.Objects;
import javax.naming.AuthenticationException;
import javax.security.auth.login.LoginException;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import tools.CertificateVerifier;

/**
 * Manages all Pkcs11 instances
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
@Log
public class LiteSignerManager {

    private final ExecutorService logInExec = Executors.newFixedThreadPool(1);
    private final ExecutorService certificateDisplayExec = Executors.newFixedThreadPool(1);
    private final ExecutorService certificateValidatorExec = Executors.newFixedThreadPool(1);
    private final ScheduledExecutorService deviceScanner = Executors.newSingleThreadScheduledExecutor();
    private volatile List<Pkcs11> pkcs11Instances = new ArrayList<>();

    private static final LiteSignerManager singleton = new LiteSignerManager();

    private DevicePanel devicePanel;
    private CertificatePanel certificatePanel;

    private Locale currentLocale;
    private volatile GuiPasswordCallback passwordCallback;
    private final String authenticated = "Logged in";
    private final String unauthenticated = "Unauthenticated";
    //Flagging if the login thread is working.
    private volatile boolean isLoginThreadBusy = false;
    //Must be able to control both description and the entry containing slotIndex and driver
    private volatile Map<String, Map.Entry<Integer, File>> slotList = new HashMap<>();

    //Alias and [Owner/Issuer/ValidFrom]
    private volatile List<Entry<String, Object[]>> currentCertificatesOnDisplay = new ArrayList<Entry<String, Object[]>>();

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
        if (!isLoginThreadBusy) {
            logInExec.submit(() -> {
                isLoginThreadBusy = true;
                if (getInstanceIfExists(slotDescription) == null) {
                    Entry<Integer, File> selectedSlot = slotList.get(slotDescription);
                    Pkcs11 smartcard = new Pkcs11(slotDescription, selectedSlot.getKey(), selectedSlot.getValue());
                    smartcard.initGuiHandler(passwordCallback);
                    ResourceBundle r = ResourceBundle.getBundle("CoreBundle", currentLocale);
                    try {
                        smartcard.login();
                        pkcs11Instances.add(smartcard);
                        SwingUtilities.invokeLater(() -> {
                            if (devicePanel.getTokensTable().getSelectedRow() != -1
                                    && slotDescription.equals(devicePanel.getTokensTable().getValueAt(devicePanel.getTokensTable().getSelectedRow(), 0))) {
                                try {
                                    printCertificates(smartcard);
                                } catch (CertificateEncodingException | KeyStoreException ex) {
                                    log.log(Level.SEVERE, "Error during the process of displaying the certificates on screen.", ex);
                                    SwingUtilities.invokeLater(() -> {
                                        JOptionPane.showMessageDialog(devicePanel.getPanelParent(), "An error occured while reading certificates!");
                                    });
                                }
                            }
                            DefaultTableModel model = devicePanel.getTokensModel();
                            model.setValueAt(authenticated, getRowByDescription(model, slotDescription), 1);
                        });
                    } catch (AuthenticationException ex) {
                        //The user closed the PIN window. Exit.
                        log.log(Level.OFF, "Pin code window closed", ex);
                    } catch (IOException ex) {
                        smartcard.closeSession();
                        if (ex.getCause() instanceof UnrecoverableKeyException && "CKR_PIN_INCORRECT".equals(ExceptionUtils.getRootCause(ex).getLocalizedMessage())) {
                            log.log(Level.FINE, "Failed to login!Incorrect pin code!", ex);
                            SwingUtilities.invokeLater(() -> {
                                JOptionPane.showMessageDialog(devicePanel.getPanelParent(), r.getString("LiteSignerManager.incorrectPin"),
                                        r.getString("LiteSignerManager.dialogMessage"), JOptionPane.WARNING_MESSAGE);
                            });
                        } else if (ex.getCause() instanceof LoginException && "CKR_PIN_LOCKED".equals(ExceptionUtils.getRootCause(ex).getLocalizedMessage())) {
                            log.log(Level.FINEST, "Failed to login >3 times! Locked pin!", ex);
                            SwingUtilities.invokeLater(() -> {
                                JOptionPane.showMessageDialog(devicePanel.getPanelParent(), r.getString("LiteSignerManager.pinLocked"),
                                        r.getString("LiteSignerManager.dialogMessage"), JOptionPane.WARNING_MESSAGE);
                            });
                        } else {
                            SwingUtilities.invokeLater(() -> {

                                log.log(Level.SEVERE, "Problem with the keystore /usb token!/ data!", ex);
                                JOptionPane.showMessageDialog(devicePanel.getPanelParent(), r.getString("LiteSignerManager.generalProblem"),
                                        r.getString("LiteSignerManager.dialogMessage"), JOptionPane.WARNING_MESSAGE);
                            });
                        }
                    } catch (NoSuchAlgorithmException | CertificateException | KeyStoreException ex) {
                        SwingUtilities.invokeLater(() -> {
                            log.log(Level.SEVERE, "Problem with the keystore /usb token!/ data!", ex);
                            JOptionPane.showMessageDialog(devicePanel.getPanelParent(), r.getString("LiteSignerManager.generalProblem"),
                                    r.getString("LiteSignerManager.dialogMessage"), JOptionPane.WARNING_MESSAGE);
                        });
                    }

                }
                isLoginThreadBusy = false;
            });
        }
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
                        SwingUtilities.invokeLater(() -> {
                            freshDeviceList.forEach((description, indexAndDriver) -> {
                                if (slotList.containsKey(description) == false) {
                                    slotList.put(description, indexAndDriver);
                                    devicePanel.getTokensModel().addRow(new Object[]{description, unauthenticated});
                                }
                            });
                            for (Iterator<Map.Entry<String, Map.Entry<Integer, File>>> it = slotList.entrySet().iterator(); it.hasNext();) {
                                String tokenDescription = it.next().getKey();
                                if (freshDeviceList.containsKey(tokenDescription) == false) {
                                    it.remove();
                                    int row = getRowByDescription(devicePanel.getTokensModel(), tokenDescription);
                                    if (devicePanel.getTokensTable().getSelectedRow() == row) {
                                        devicePanel.getTokensTable().clearSelection();
                                    }
                                    devicePanel.getTokensModel().removeRow(row);
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

    public void checkIfCertificateHasChain(int row) {
        certificateValidatorExec.submit(() -> {
            try {
                Pkcs11 smartcard = getInstanceIfExists(devicePanel.getTokensTable().getValueAt(devicePanel.getTokensTable().getSelectedRow(), 0).toString());
                if (smartcard != null) {
                    PKIXCertPathBuilderResult result = CertificateVerifier.getInstance().validateCertificate(smartcard.getCertificate(currentCertificatesOnDisplay.get(row).getKey()));
                    if (result == null) {
                        throw new CertificateVerificationException("The certificate has no certification chain!");
                    }
                }
            } catch (KeyStoreException ex) {
                JOptionPane.showMessageDialog(certificatePanel.getPanelParent(), ex.getMessage());
            } catch (CertificateVerificationException ex) {
                certificatePanel.getCertificateTable().clearSelection();
                JOptionPane.showMessageDialog(certificatePanel.getPanelParent(), ex.getMessage());
            }
        });

    }

    public void displayCertificates(String slotDescription) {
        certificateDisplayExec.submit(() -> {
            Pkcs11 smartcard = getInstanceIfExists(slotDescription);
            if (smartcard != null) {
                SwingUtilities.invokeLater(() -> {
                    try {
                        printCertificates(smartcard);
                    } catch (CertificateEncodingException | KeyStoreException ex) {
                        SwingUtilities.invokeLater(() -> {
                            JOptionPane.showMessageDialog(devicePanel.getPanelParent(), "An error occured while reading certificates!");
                        });
                    }
                });
            }
        });
    }

    private void printCertificates(Pkcs11 smartcard) throws CertificateEncodingException, KeyStoreException {
        currentCertificatesOnDisplay.clear();
        for (X509Certificate certificate : smartcard.listCertificates()) {
            Object[] row = new Object[3];
            X500Name subject = new JcaX509CertificateHolder(certificate).getSubject();
            RDN cn = subject.getRDNs(BCStyle.CN)[0];
            String subjectCN = IETFUtils.valueToString(cn.getFirst().getValue());
            row[0] = subjectCN;

            X500Name publisher = new JcaX509CertificateHolder(certificate).getIssuer();
            RDN cn1 = publisher.getRDNs(BCStyle.CN)[0];
            String issuerCN = IETFUtils.valueToString(cn1.getFirst().getValue());
            row[1] = issuerCN;

            SimpleDateFormat formatter = new SimpleDateFormat("dd-MM-yyyy kk:mm z");
            Date date = certificate.getNotBefore();
            String format = formatter.format(date);
            row[2] = format;

            currentCertificatesOnDisplay.add(new SimpleEntry<>(smartcard.getCertificateAlias(certificate), row));
            certificatePanel.getTableModel().addRow(row);
        }
    }

    public void clearCertificateList() {
        certificatePanel.getTableModel().setRowCount(0);
    }

    /**
     * Descriptions are always located on the first column. Traversing only
     * rows.
     *
     * @param model Model to be traversed.
     * @param description The value to be matched.
     * @return Index of the value to be found or -1 if the value was not found.
     */
    private int getRowByDescription(TableModel model, Object description) {
        for (int i = model.getRowCount() - 1; i >= 0; --i) {
            if (model.getValueAt(i, 0).equals(description)) {
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

    /**
     * Shuts down the scanning thread. Then waits for 3 seconds before returning
     * control to the caller (EDT).
     */
    public void cancelDeviceScanner() {
        deviceScanner.shutdown();
        try {
            deviceScanner.awaitTermination(3, TimeUnit.SECONDS);
        } catch (InterruptedException ex) {
            log.log(Level.SEVERE, "Failed to clean things up before closing the application!", ex);
        }
    }

}
