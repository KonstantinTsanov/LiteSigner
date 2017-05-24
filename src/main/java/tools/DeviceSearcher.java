/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tools;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.logging.Level;
import java.util.prefs.Preferences;
import lombok.extern.java.Log;
import org.apache.commons.lang3.NotImplementedException;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
@Log
public class DeviceSearcher {

    private static Properties driversList = new Properties();
    private static final String key = "Paths";
    private static Preferences driverPaths;

    static {
        driverPaths = Preferences.userNodeForPackage(DeviceSearcher.class);
        try {
            driversList.load(DeviceSearcher.class.getResourceAsStream("/" + DeviceSearcher.class.getSimpleName() + ".properties"));
        } catch (IOException ex) {
            log.log(Level.WARNING, "Couldn't load the driver list!", ex);
        }
        if (driverPaths.get(key, null) == null) {
            driverPaths.put(key, System.getenv("WINDIR") + "\\system32");
        }
    }

    private static List<String> GetAllDrivers() {
        //todo
        throw new NotImplementedException("Not yet implemented");
    }

    //TODO
    public static List<String> SearchForDevices() {
        String[] paths = driverPaths.get(key, null).split(";", -1);
        String driver;
        List<String> list = new ArrayList<>();
        for (String path : paths) {
            for (Map.Entry<Object, Object> entry : driversList.entrySet()) {
                driver = path.concat("\\").concat(entry.getValue().toString()).concat(".dll");
                PKCS11 p11 = null;
                try {
                    p11 = PKCS11.getInstance(driver, "C_GetFunctionList", null, false);
                    try {
                        long[] slots = p11.C_GetSlotList(true);
                        if (slots.length > 0) {
                            for (int i = 0; i < slots.length ; i++) {
                                list.add(new String(p11.C_GetSlotInfo(slots[i]).slotDescription).trim());
                            }
                        }
                    } catch (PKCS11Exception ex) {
                        throw new RuntimeException(ex);
                    }
                } catch (IOException ex) {
                    //log.log(Level.SEVERE, "Key: " + entry.getKey() + " value: "+ entry.getValue(), ex);
                    continue;
                } catch (PKCS11Exception ex) {
                    log.log(Level.SEVERE, "PKCS11 error!", ex);
                }
            }
        }
        //TODO
        return list;
    }

    public static void AddNewPathToDriver(String path) throws IllegalArgumentException {
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

    public static String[] GetAllDriverPaths() {
        return driverPaths.get(key, null).split(";", -1);
    }
}
