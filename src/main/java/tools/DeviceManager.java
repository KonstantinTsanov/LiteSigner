/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tools;

import java.io.File;
import java.io.IOException;
import java.util.AbstractMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.logging.Level;
import java.util.prefs.Preferences;
import lombok.extern.java.Log;
import org.usb4java.Context;
import org.usb4java.DeviceList;
import org.usb4java.LibUsb;
import org.usb4java.LibUsbException;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;

/**
 * Using singleton because of NoClassDefFoundError exeption that happened when
 * the class was static with a static block
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
@Log
public class DeviceManager {

    private Properties driversList = new Properties();
    private final String key = "Paths";
    private Preferences driverPaths;
    private static DeviceManager singleton = new DeviceManager();

    private int pluggedUsbCount = 0;

    private volatile boolean exiting = false;
    //Javax4usb context
    static Context context = new Context();

    static {
        int result = LibUsb.init(context);
        if (result < 0) {
            throw new LibUsbException("Unable to initialize libusb", result);
        }
    }

    public static DeviceManager getInstance() {
        return singleton;
    }

    private void initialize() {
        driverPaths = Preferences.userNodeForPackage(DeviceManager.class);
        try {
            driversList.load(DeviceManager.class.getResourceAsStream("/" + "DeviceManager.properties"));
        } catch (IOException ex) {
            log.log(Level.WARNING, "Couldn't load the driver list!", ex);
        }
        if (driverPaths.get(key, null) == null) {
            driverPaths.put(key, System.getenv("WINDIR") + "\\system32");
        }
    }

    //TODO
    public synchronized Map<String, Map.Entry<Integer, File>> SearchForDevices() throws PKCS11Exception {
        initialize();
        String[] paths = driverPaths.get(key, null).split(";", -1);
        String driver;
        //The first string represents the slot description. The second represents both the slotListIndex and the driver for the token.
        Map<String, Map.Entry<Integer, File>> tokensDescription = new HashMap<>();
        for (String path : paths) {
            for (Map.Entry<Object, Object> entry : driversList.entrySet()) {
                driver = path.concat("\\").concat(entry.getValue().toString()).concat(".dll");
                PKCS11 p11 = null;
                try {
                    p11 = PKCS11.getInstance(driver, "C_GetFunctionList", null, false);
                    long[] slots = p11.C_GetSlotList(true);
                    if (slots.length > 0) {
                        for (int i = 0; i < slots.length; i++) {
                            Map.Entry<Integer, File> slotIdAndDriver = new AbstractMap.SimpleEntry<>(i, new File(driver));
                            tokensDescription.put(new String(p11.C_GetSlotInfo(slots[i]).slotDescription).trim(), slotIdAndDriver);
                        }
                    }
                } catch (IOException ex) {
                    // I don't care. - there's no plugged device that works with this dll. continue.
                }
            }
        }
        return tokensDescription;
    }

    public Map<String, Map.Entry<Integer, File>> CheckDeviceStatus(List<Map.Entry<Integer, File>> slotIndexAndDriver) {
        PKCS11 p11 = null;
        for (Map.Entry<Integer, File> deviceProperties : slotIndexAndDriver) {
            //p11 = PKCS11.getInstance(deviceProperties.getValue(), "C_GetFunctionList", null, false);
        }
        return null;
    }

    public void scanUsbDevices() {
        // Read the USB device list
        DeviceList list = new DeviceList();
        int newUsbCount = LibUsb.getDeviceList(context, list);
        if (newUsbCount < 0) {
            throw new LibUsbException("Unable to get device list", newUsbCount);
        }
        //TODO
        //if()
        if (exiting) {
            LibUsb.exit(context);
        }
    }

    public void AddNewPathToDriver(String path) throws IllegalArgumentException {
        Objects.requireNonNull(path, "path must not be null");

        String currentPaths = driverPaths.get(key, null);
        String[] paths = currentPaths.split(";", -1);
        for (String p : paths) {
            if (p.equals(path)) {
                throw new IllegalArgumentException("The path already exists.");
            }
        }
        String newPaths = currentPaths + ";" + path;
        driverPaths.put(key, newPaths);
    }

    public String[] GetAllDriverPaths() {
        return driverPaths.get(key, null).split(";", -1);
    }
}
