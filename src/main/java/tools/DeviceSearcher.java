/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tools;

import java.io.IOException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.lang3.NotImplementedException;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public class DeviceSearcher {

    //TODO
    public static List<String> List() {
        for (String dll : DeviceSearcher.List()) {
            PKCS11 p11;
            try {
                p11 = PKCS11.getInstance(dll, "C_GetFunctionList", null, true);
                long[] slots = p11.C_GetSlotList(true);
                System.out.println(p11.C_GetInfo());
            } catch (IOException ex) {
                Logger.getLogger(DeviceSearcher.class.getName()).log(Level.SEVERE, null, ex);
            } catch (PKCS11Exception ex) {
                Logger.getLogger(DeviceSearcher.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return null;
    }
}
