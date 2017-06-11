/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package core;

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
import javax.swing.DefaultListModel;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import lombok.extern.java.Log;
import pkcs.Pkcs11;
import sun.security.pkcs11.wrapper.PKCS11Exception;
import tools.DeviceManager;
import org.apache.commons.lang3.exception.ExceptionUtils;
import java.util.Locale;
import java.util.ResourceBundle;
import callbacks.SelectingDevicePanel;

/**
 * Manages all Pkcs11 instances
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
@Log
public class LiteSignerManager {

    private final ExecutorService logInExec = Executors.newFixedThreadPool(1);
    private final ScheduledExecutorService deviceScanner = Executors.newSingleThreadScheduledExecutor();
    private final List<Pkcs11> pkcs11Instances = new ArrayList<>();

    private static final LiteSignerManager singleton = new LiteSignerManager();

    private SelectingDevicePanel selectingDevicePanel;

    private Locale currentLocale;
    private GuiPasswordCallback passwordCallback;
    private final String loggedIn = " - Logged In";
    //Must be able to control both description and the entry containing slotIndex and driver
    Map<String, Map.Entry<Integer, File>> slotList = new HashMap<>();

    /**
     * Must be called before executing other methods in the class.
     *
     * @param selectingDeviceJPanel The output jframe for the device scanner and
     * the input for the device selection.
     * @param passwordCallback The implementation of the GuiPasswordCallback
     * interface.
     */
    public void setComponents(SelectingDevicePanel selectingDeviceJPanel, GuiPasswordCallback passwordCallback) {
        this.selectingDevicePanel = selectingDeviceJPanel;
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
        logInExec.submit(() -> {
            Entry<Integer, File> selectedSlot = slotList.get(slotDescription);
            Pkcs11 smartcard = new Pkcs11(slotDescription, selectedSlot.getKey(), selectedSlot.getValue());
            smartcard.initGuiHandler(passwordCallback);
            try {
                smartcard.login();
                pkcs11Instances.add(smartcard);
                SwingUtilities.invokeLater(() -> {
                    DefaultListModel<String> model = selectingDevicePanel.getTokensModel();
                    model
                            .setElementAt(model
                                    .elementAt(model
                                            .indexOf(slotDescription))
                                    .concat(loggedIn), model.indexOf(slotDescription));
                });
                //TODO FIX
//
            } catch (KeyStoreException ex) {
                smartcard.closeSession();
                ResourceBundle r = ResourceBundle.getBundle("CoreBundle", currentLocale);
                if ("CKR_PIN_INCORRECT".equals(ExceptionUtils.getRootCause(ex).getLocalizedMessage())) {
                    SwingUtilities.invokeLater(() -> {
                        JOptionPane.showMessageDialog(selectingDevicePanel.getLayoutParent(), r.getString("LiteSignerManager.incorrectPin"),
                                r.getString("LiteSignerManager.dialogMessage"), JOptionPane.WARNING_MESSAGE);
                    });
                } else if ("CKR_PIN_LOCKED".equals(ExceptionUtils.getRootCause(ex).getLocalizedMessage())) {
                    SwingUtilities.invokeLater(() -> {
                        JOptionPane.showMessageDialog(selectingDevicePanel.getLayoutParent(), r.getString("LiteSignerManager.pinLocked"),
                                r.getString("LiteSignerManager.dialogMessage"), JOptionPane.WARNING_MESSAGE);
                    });
                } else {
                    SwingUtilities.invokeLater(() -> {
                        JOptionPane.showMessageDialog(selectingDevicePanel.getLayoutParent(),
                                r.getString("LiteSignerManager.dialogMessage"), "There is a problem with the device.", JOptionPane.WARNING_MESSAGE);
                    });
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
                                    //throws nullpointer at addelement
                                    selectingDevicePanel.getTokensModel().addElement(description);
                                }
                            });
                            for (Iterator<Map.Entry<String, Map.Entry<Integer, File>>> it = slotList.entrySet().iterator(); it.hasNext();) {
                                String description = it.next().getKey();
                                if (freshDeviceList.containsKey(description) == false) {
                                    //throws nullpointer
                                    it.remove();
                                    selectingDevicePanel.getTokensModel().removeElement(description);
                                    //remove logged in
                                    selectingDevicePanel.getTokensModel().removeElement(description.concat(loggedIn));
                                }
                            }
                        });
                    }
                } catch (PKCS11Exception ex) {
                    SwingUtilities.invokeLater(() -> {
                        JOptionPane.showMessageDialog(selectingDevicePanel.getLayoutParent(), "There is a problem with the device.");
                    });
                }

            }
        };
        deviceScanner.scheduleAtFixedRate(t, 0, n, TimeUnit.SECONDS);
        t.start();
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
