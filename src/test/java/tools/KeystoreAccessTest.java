/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tools;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author KTsan
 */
public class KeystoreAccessTest {
    
    public KeystoreAccessTest() {
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
     * Test of keystore method, of class KeystoreAccess.
     */
    @org.junit.Test
    public void testKeystore() {
        System.out.println("keystore");
        KeystoreAccess instance = new KeystoreAccess();
        instance.keystore();
        // TODO review the generated test code and remove the default call to fail.

    }
    
}
