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
import callbacks.SelectingDeviceComponent;
import tools.DeviceManager;

/**
 * Manages all Pkcs11 instances
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
@Log
public class LiteSignerManager {

    private ExecutorService logInExec = Executors.newFixedThreadPool(1);
    private final ScheduledExecutorService deviceScanner = Executors.newSingleThreadScheduledExecutor();
    private List<Pkcs11> pkcs11Instances = new ArrayList<>();

    private static LiteSignerManager singleton = new LiteSignerManager();

    private SelectingDeviceComponent selectingDeviceJPanel;

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
    public void setComponents(SelectingDeviceComponent selectingDeviceJPanel, GuiPasswordCallback passwordCallback) {
        this.selectingDeviceJPanel = selectingDeviceJPanel;
        this.passwordCallback = passwordCallback;
    }

    private LiteSignerManager() {

    }

    public static LiteSignerManager getInstance() {
        return singleton;
    }

    public void deviceLogIn(String slotDescription) {
        logInExec.submit(new Runnable() {
            @Override
            public void run() {
                Entry<Integer, File> selectedSlot = slotList.get(slotDescription);
                Pkcs11 smartcard = new Pkcs11(slotDescription, selectedSlot.getKey(), selectedSlot.getValue());
                smartcard.initGuiHandler(passwordCallback);
                try {
                    smartcard.login();
                    pkcs11Instances.add(smartcard);
                    SwingUtilities.invokeLater(new Runnable() {
                        @Override
                        public void run() {
                            DefaultListModel<String> model = selectingDeviceJPanel.getTokensModel();
                            model
                                    .setElementAt(model
                                            .elementAt(model
                                                    .indexOf(slotDescription))
                                            .concat(loggedIn), model.indexOf(slotDescription));
                        }
                    });
                    //TODO FIX
//                    
                } catch (KeyStoreException ex) {
                    SwingUtilities.invokeLater(() -> {
                        JOptionPane.showMessageDialog(selectingDeviceJPanel.getComponentParent(), "There is a problem with the device.");
                    });
                }
                selectingDeviceJPanel.getComponentParent().repaint();
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
                                    selectingDeviceJPanel.getTokensModel().addElement(description);
                                }
                            });
                            for (Iterator<Map.Entry<String, Map.Entry<Integer, File>>> it = slotList.entrySet().iterator(); it.hasNext();) {
                                String description = it.next().getKey();
                                if (freshDeviceList.containsKey(description) == false) {
                                    //throws nullpointer
                                    it.remove();
                                    selectingDeviceJPanel.getTokensModel().removeElement(description);
                                    //remove logged in
                                    selectingDeviceJPanel.getTokensModel().removeElement(description.concat(loggedIn));
                                }
                            }
                        });
                    }
                } catch (PKCS11Exception ex) {
                    SwingUtilities.invokeLater(() -> {
                        JOptionPane.showMessageDialog(selectingDeviceJPanel.getComponentParent(), "There is a problem with the device.");
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
