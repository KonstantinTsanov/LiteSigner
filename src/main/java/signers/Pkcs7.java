/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package signers;

import exceptions.TimestampingException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import lombok.extern.java.Log;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableFile;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
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
    private URL _timestampAddress;

    public Pkcs7(Pkcs1_ pkcs1x, String alias, File input, File output, URL timestampAddress) {
        _pkcs1x = pkcs1x;
        _alias = alias;
        _input = input;
        _output = output;
        _timestampAddress = timestampAddress;
    }

    @Override
    public void sign(boolean attached) {
        try {
            Objects.requireNonNull(_input);
            Objects.requireNonNull(_output);

            X509Certificate cert;
            cert = (X509Certificate) _pkcs1x.get_certKeyStore().getCertificate(_alias);
            List certList = new ArrayList();
            certList.add(cert);
            Store certs = new JcaCertStore(certList);
            CMSProcessableFile inputFile = new CMSProcessableFile(_input);
            char[] pin = _pkcs1x.get_passwordCallback().getPin();
            ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA")
                    .setProvider(_pkcs1x.get_provider()).build((PrivateKey) _pkcs1x.get_certKeyStore()
                    .getKey(_alias, pin));
            //todo
            Security.addProvider(new BouncyCastleProvider());
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(sha1Signer, cert));

            gen.addCertificates(certs);

            CMSSignedData sigData = gen.generate(inputFile, attached);
            //Timestamping
            if (_timestampAddress != null) {
                CMSSignedData signedTimestampData = new CMSSignedData(sigData.toASN1Structure());
                Collection<SignerInformation> ss = signedTimestampData.getSignerInfos().getSigners();
                SignerInformation si = ss.iterator().next();
                ASN1EncodableVector timestampVector = new ASN1EncodableVector();
                MessageDigest md = MessageDigest.getInstance("SHA1", "BC");
                TimeStampResponse response = timestampRequest(md.digest(si.getSignature()), _timestampAddress.toURI());
                TimeStampToken timestampToken = response.getTimeStampToken();
                Attribute a = new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, new DERSet(ASN1Primitive.fromByteArray(timestampToken.getEncoded())));
                timestampVector.add(a);
                AttributeTable at = new AttributeTable(timestampVector);
                si = SignerInformation.replaceUnsignedAttributes(si, at);
                ss.clear();
                ss.add(si);
                SignerInformationStore newSignerStore = new SignerInformationStore(ss);
                sigData = CMSSignedData.replaceSigners(signedTimestampData, newSignerStore);
            }
            try (FileOutputStream fileOuputStream = new FileOutputStream(_output)) {
                fileOuputStream.write(sigData.getEncoded());
                fileOuputStream.flush();
            }
//TODO
        } catch (Exception ex) {
            log.log(Level.SEVERE, "Failed to sign!", ex);
            ex.printStackTrace(System.out);
        }
    }

    private static TimeStampResponse timestampRequest(byte[] data, URI uri) throws TimestampingException {
        try {
            TimeStampRequestGenerator reqgen = new TimeStampRequestGenerator();
            reqgen.setCertReq(true);
            TimeStampRequest req = reqgen.generate(TSPAlgorithms.SHA1, data);
            byte request[] = req.getEncoded();
            HttpURLConnection conn = (HttpURLConnection) uri.toURL().openConnection();
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            conn.setDoOutput(true);
            conn.setDoInput(true);
            //conn.setUseCaches(false);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-type", "application/timestamp-query");
            conn.setRequestProperty("Content-length", String.valueOf(request.length));
            try (OutputStream out = conn.getOutputStream()) {
                out.write(request);
                out.flush();
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
            if (conn.getResponseCode() >= 400) {
                throw new IOException("Unable to complete the timestamping due to HTTP error: " + conn.getResponseCode() + " - " + conn.getResponseMessage());
            }
            InputStream in = conn.getInputStream();
            TimeStampResp resp = TimeStampResp.getInstance(new ASN1InputStream(in).readObject());
            TimeStampResponse response = new TimeStampResponse(resp);
            response.validate(req);
            if (response.getStatus() != 0) {
                throw new IOException("Unable to complete the timestamping due to an invalid response (" + response.getStatusString() + ")");
            }
            return response;
        } catch (Exception ex) {
            throw new TimestampingException("Unable to complete the timestamping", ex);
        }
    }

    @Override
    public void verify() {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
