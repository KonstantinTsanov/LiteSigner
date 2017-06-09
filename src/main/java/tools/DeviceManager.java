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
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Properties;
import java.util.logging.Level;
import java.util.prefs.Preferences;
import lombok.extern.java.Log;
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

    private final Properties driversList = new Properties();
    private final String key = "Paths";
    private Preferences driverPaths;
    private static final DeviceManager singleton = new DeviceManager();

    //Keeps track of the number of attached USB devices. Updated after each  countAttachedUSBDevices() call.
    private int attachedUSBCount = Integer.MIN_VALUE;

    //The first string represents the slot description. The entry contains an integer which represents the slotIndex and a File which is the Path to driver.
    Map<String, Entry<Integer, File>> deviceMap = new HashMap<>();

    static {
        int result = LibUsb.init(null);
        if (result < 0) {
            throw new LibUsbException("Unable to initialize libusb", result);
        }
    }

    public static DeviceManager getInstance() {
        return singleton;
    }

    private void initDriverListAndPaths() {
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

    /**
     * Scans for ANY changes in the USB devices count. If any changes are
     * present invokes additional methods. If no changes are present returns
     * null.
     *
     * @return List of currently attached usb tokens if any USB changes have
     * been detected or null otherwise.
     * @throws PKCS11Exception
     */
    public synchronized Map<String, Entry<Integer, File>> scanForUSBDevices() throws PKCS11Exception {
        int newUSBCount = countAttachedUSBDevices();
        if (newUSBCount > attachedUSBCount) {
            attachedUSBCount = newUSBCount;
            return scanAllDirectories();
        } else if (newUSBCount < attachedUSBCount) {
            attachedUSBCount = newUSBCount;
            return checkDeviceStatus();
        } else {
            return null;
        }
    }

    /**
     * Scans all current directories for any known drivers and checks if there's
     * any device that works with this driver. Used when a new device has been
     * attached.
     *
     * @return List of attached devices
     * @throws PKCS11Exception
     */
    private Map<String, Entry<Integer, File>> scanAllDirectories() throws PKCS11Exception {
        initDriverListAndPaths();
        String[] paths = driverPaths.get(key, null).split(";", -1);
        String driver;
        for (String path : paths) {
            for (Entry<Object, Object> entry : driversList.entrySet()) {
                driver = path.concat("\\").concat(entry.getValue().toString()).concat(".dll");
                PKCS11 p11 = null;
                try {
                    p11 = PKCS11.getInstance(driver, "C_GetFunctionList", null, false);
                    long[] slots = p11.C_GetSlotList(true);
                    if (slots.length > 0) {
                        for (int i = 0; i < slots.length; i++) {
                            Entry<Integer, File> slotIdAndDriver = new AbstractMap.SimpleEntry<>(i, new File(driver));
                            deviceMap.put(new String(p11.C_GetSlotInfo(slots[i]).slotDescription).trim(), slotIdAndDriver);
                        }
                    }
                } catch (IOException ex) {
                    // I don't care. - there's no plugged device that works with this dll. continue.
                }
            }
        }
        return deviceMap;
    }

    /**
     * Checks if a device /identified by both slotIndex and driver/ is still
     * available. Called when any USB device has been removed to check if its a
     * token and to eventually remove it from the list of attached devices.
     *
     * @return Map containing the updated list of devices.
     */
    private Map<String, Entry<Integer, File>> checkDeviceStatus() throws PKCS11Exception {
        PKCS11 p11 = null;
        Entry<String, Entry<Integer, File>> device = null;
        Map<String, Entry<Integer, File>> newDeviceMap = new HashMap<>();
        String driver;
        for (Iterator<Entry<String, Entry<Integer, File>>> iterator = deviceMap.entrySet().iterator(); iterator.hasNext();) {
            try {
                device = iterator.next();
                driver = device.getValue().getValue().toString();
                p11 = PKCS11.getInstance(driver, "C_GetFunctionList", null, false);
                long[] slots = p11.C_GetSlotList(true);
                if (slots.length > 0) {
                    for (int i = 0; i < slots.length; i++) {
                        Entry<Integer, File> slotIdAndDriver = new AbstractMap.SimpleEntry<>(i, new File(driver));
                        newDeviceMap.put(new String(p11.C_GetSlotInfo(slots[i]).slotDescription).trim(), slotIdAndDriver);
                    }
                }
                deviceMap = newDeviceMap;
            } catch (IOException ex) {
                deviceMap.remove(device.getKey());
            }
        }
        return deviceMap;
    }

    /**
     * Counts all currently attached to the computer USB devices.
     *
     * @return number of currently attached USB devices.
     */
    private int countAttachedUSBDevices() {
        DeviceList list = new DeviceList();
        int newUsbCount = LibUsb.getDeviceList(null, list);
        if (newUsbCount < 0) {
            throw new LibUsbException("Unable to get device list", newUsbCount);
        }
        return newUsbCount;
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
