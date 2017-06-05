/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pkcs;

import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public class Pkcs12 extends Pkcs1_ {

    @Override
    public void login() throws KeyStoreException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    //TODO

    //Да премахна метода ако имплементацията е същата както в pkcs11
    @Override
    public List<String> listAliases() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    //Да премахна метода ако имплементацията е същата както в pkcs11
    @Override
    public X509Certificate getCertificate(String alias) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
