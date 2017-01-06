/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pkcs;

import callbacks.impl.PasswordJOptionPane;
import java.io.File;
import java.security.cert.X509Certificate;
import java.util.List;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public class Pkcs11Test {

    public Pkcs11Test() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of setDriver method, of class Pkcs11.
     */
    @Test
    public void testSetDriver() {
        PasswordJOptionPane pane = new PasswordJOptionPane(null);
        pane.getPassword();
        System.out.println("setDriver");
        File driver = new File("C:\\WINDOWS\\System32\\acospkcs11.dll");
        Pkcs11.setDriver(driver);
        // TODO review the generated test code and remove the default call to fail.
    }

    /**
     * Test of listCertificates method, of class Pkcs11.
     */
    @Test
    public void testListCertificates() {
        testSetDriver();
        System.out.println("listCertificates");
        Pkcs11 instance = new Pkcs11();
        List<X509Certificate> list = instance.listCertificates();
        for (X509Certificate cert : list) {
            System.out.println(cert.getSubjectX500Principal().getName());
        }
    }

}
