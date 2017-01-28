/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package enums;

import java.io.File;
import pkcs.Pkcs11;
import pkcs.Pkcs12;
import pkcs.Pkcs1_;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public enum KeyStoreType {
    PKCS11 {
        @Override
        Pkcs1_ getNewPkcsObject(File driver) {
            return new Pkcs11(driver);
        }
    }, PKCS12 {
        @Override
        Pkcs1_ getNewPkcsObject(File path) {
            //TODO pkcs12 constructor
            return new Pkcs12();
        }
    };

    abstract Pkcs1_ getNewPkcsObject(File file);
}
