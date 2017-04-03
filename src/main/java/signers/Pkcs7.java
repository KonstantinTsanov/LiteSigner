/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package signers;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import lombok.extern.java.Log;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableFile;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import pkcs.Pkcs1_;

/**
 *
 * @author KTsan
 */
@Log
public class Pkcs7 extends Signer {

    private final File _input;
    private final File _output;
    private final String _alias;
    private X509Certificate _cert;
    Callback[] callbacks = {new PasswordCallback("password", false)};

    public Pkcs7(Pkcs1_ pkcs1x, String alias, File input, File output) {
        _pkcs1x = pkcs1x;
        _alias = alias;
        _input = input;
        _output = output;
    }

    @Override
    public void sign() {
        try {
            Objects.requireNonNull(_input);
            Objects.requireNonNull(_output);
            
            X509Certificate cert;
            cert = (X509Certificate) _pkcs1x.get_certKeyStore().getCertificate(_alias);
            List certList = new ArrayList();
            certList.add(cert);
            Store certs = new JcaCertStore(certList);
            CMSProcessableFile inputFile = new CMSProcessableFile(_input);
            _pkcs1x.get_guiHandler().handle(callbacks);
            char[] pin = ((PasswordCallback) callbacks[0]).getPassword();
            ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA")
                    .setProvider(_pkcs1x.get_provider()).build((PrivateKey) _pkcs1x.get_certKeyStore()
                    .getKey(_alias, pin));
            Security.addProvider(new BouncyCastleProvider());
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(sha1Signer, cert));

            gen.addCertificates(certs);

            CMSSignedData sigData = gen.generate(inputFile, false);

            FileOutputStream fileOuputStream = new FileOutputStream(_output);
            fileOuputStream.write(sigData.getEncoded());
            fileOuputStream.flush();
            fileOuputStream.close();

        } catch (CertificateEncodingException ex) {
            Logger.getLogger(Pkcs7.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            log.log(Level.SEVERE, "The keystore hasnt been loaded!", ex);
            throw new RuntimeException("The keystore hasnt been loaded!", ex);
        } catch (CMSException ex) {
            Logger.getLogger(Pkcs7.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Pkcs7.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnsupportedCallbackException ex) {
            Logger.getLogger(Pkcs7.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Pkcs7.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnrecoverableKeyException ex) {
            Logger.getLogger(Pkcs7.class.getName()).log(Level.SEVERE, null, ex);
        } catch (OperatorCreationException ex) {
            Logger.getLogger(Pkcs7.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    public void verify() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
