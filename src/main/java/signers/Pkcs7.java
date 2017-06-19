/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package signers;

import exceptions.CertificateVerificationException;
import exceptions.SignatureValidationException;
import exceptions.TimestampingException;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.ResourceBundle;
import java.util.logging.Level;
import lombok.extern.java.Log;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSProcessableFile;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.bc.BcRSASignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;
import pkcs.Pkcs1_;
import tools.CertificateVerifier;

/**
 *
 * @author KTsan
 */
@Log
public class Pkcs7 extends Signer {

    private File _input;
    private File _output;
    private String _alias;
    private URL _timestampAddress;
    private Locale locale;

    public Pkcs7(Locale locale) {
        this.locale = locale;
    }

    public Pkcs7(Pkcs1_ pkcs1x, String alias, File input, File output, URL timestampAddress, Locale locale) {
        this.locale = locale;
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
            //TODO
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
    public String validate(File pkcs7, File signedFile) throws IOException, SignatureValidationException {
        if (signedFile == null) {
            try (InputStream is = new FileInputStream(pkcs7)) {
                return validateAttachedSignature(is);
            } catch (CertificateVerificationException ex) {
                return validateDetachedSignature(pkcs7, signedFile);
            }
        } else {
            return validateDetachedSignature(pkcs7, signedFile);
        }
    }

    private String validateAttachedSignature(InputStream attached) throws CertificateVerificationException {
        String validationResult = "";
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        try {
            CMSSignedData cmsSignedData = new CMSSignedData(attached);
            SignerInformationStore signers = cmsSignedData.getSignerInfos();
            Collection<SignerInformation> c = signers.getSigners();
            boolean result = false;
            for (SignerInformation signer : c) {
                SignerId signerId = signer.getSID();
                Collection certCollection = cmsSignedData.getCertificates().getMatches(signerId);

                Iterator certIt = certCollection.iterator();
                X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate((X509CertificateHolder) certIt.next());
                result = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));
                if (!result) {
                    validationResult = "The signature is not valid!";
                    return validationResult;
                }
                CertificateVerifier.getInstance().validateCertificate(cert);
                validationResult = validationResult.concat("Certificate validation passed. \nCertificate is valid.");
                //TIMESTAMP PART
                AttributeTable unsignedAttributes = signer.getUnsignedAttributes();
                if (unsignedAttributes != null) {
                    Attribute timestampAttribute = unsignedAttributes.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
                    if (timestampAttribute == null) {
                        validationResult = validationResult.concat("\nThe signature contains no timestamp");
                        log.log(Level.FINE, "The signature contains no timestamp.");
                    } else {
                        ASN1Encodable dob = timestampAttribute.getAttrValues().getObjectAt(0);
                        CMSSignedData signedData = new CMSSignedData(dob.toASN1Primitive().getEncoded());
                        TimeStampToken tst = new TimeStampToken(signedData);
                        Collection tstSigners = tst.toCMSSignedData().getSignerInfos().getSigners();
                        TimeStampTokenInfo timestampInfo = validateTimeStamp(tstSigners, tst);
                        validationResult = validationResult.concat("\nThe signature contains a timestamp.");
                        validationResult = validationResult.concat(String.format("\nTSA: %s\n Time: %s", timestampInfo.getTsa().toString(), timestampInfo.getGenTime().toString()));
                    }
                } else {
                    validationResult = validationResult.concat("\nThe signature contains no timestamp.");
                }
            }
            return validationResult;
        } catch (CertificateVerificationException ex) {
            throw ex;
        } catch (IOException | CertificateException | CMSException | OperatorCreationException | TSPException | StoreException ex) {
            log.log(Level.SEVERE, "An error occured while validating the signature!", ex);
            ResourceBundle r = ResourceBundle.getBundle("CoreBundle", locale);
            throw new CertificateVerificationException(r.getString("signatureValidationFailedError"), ex);
        }
    }

    private String validateDetachedSignature(File pkcs7, File signedFile) throws SignatureValidationException {
        String validationResult = "";
        Security.addProvider(new BouncyCastleProvider());
        try {
            byte[] Sig_Bytes = new byte[(int) pkcs7.length()];
            try (DataInputStream in = new DataInputStream(new FileInputStream(pkcs7))) {
                in.readFully(Sig_Bytes);
                in.close();
            }
            byte[] Data_Bytes = new byte[(int) signedFile.length()];
            try (DataInputStream input = new DataInputStream(new FileInputStream(signedFile))) {
                input.readFully(Data_Bytes);
                input.close();
            }
            try {
                CMSSignedData cms = new CMSSignedData(new CMSProcessableByteArray(Data_Bytes), Sig_Bytes);
                Store certs = cms.getCertificates();
                SignerInformationStore signers = cms.getSignerInfos();
                Iterator it = signers.getSigners().iterator();
                if (it.hasNext()) {
                    SignerInformation signer = (SignerInformation) it.next();
                    X509CertificateHolder cert = (X509CertificateHolder) certs.getMatches(signer.getSID()).iterator().next();

                    SignerInformationVerifier verifier = new BcRSASignerInfoVerifierBuilder(
                            new DefaultCMSSignatureAlgorithmNameGenerator(),
                            new DefaultSignatureAlgorithmIdentifierFinder(),
                            new DefaultDigestAlgorithmIdentifierFinder(),
                            new BcDigestCalculatorProvider()).build(cert);
                    byte[] data = (byte[]) cms.getSignedContent().getContent();
                    if (signer.verify(verifier)) {
                        validationResult = "Signature verified sucessfully.";
                    } else {
                        validationResult = "Signature verification failed!";
                        return validationResult;
                    }
                    AttributeTable unsignedAttributes = signer.getUnsignedAttributes();
                    if (unsignedAttributes != null) {
                        Attribute timestampAttribute = unsignedAttributes.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
                        if (timestampAttribute == null) {
                            validationResult = validationResult.concat("\nThe signature contains no timestamp");
                            log.log(Level.FINE, "The signature contains no timestamp.");
                        } else {
                            ASN1Encodable dob = timestampAttribute.getAttrValues().getObjectAt(0);
                            CMSSignedData signedData = new CMSSignedData(dob.toASN1Primitive().getEncoded());
                            TimeStampToken tst = new TimeStampToken(signedData);
                            Collection tstSigners = tst.toCMSSignedData().getSignerInfos().getSigners();
                            TimeStampTokenInfo timestampInfo = validateTimeStamp(tstSigners, tst);
                            validationResult = validationResult.concat("\nThe signature contains a timestamp.");
                            validationResult = validationResult.concat(String.format("\nTSA: %s\n Time: %s", timestampInfo.getTsa().toString(), timestampInfo.getGenTime().toString()));
                        }
                    } else {
                        validationResult = validationResult.concat("\nThe signature contains no timestamp.");
                    }
                }

            } catch (Exception e) {
                throw new SignatureValidationException("Could not validate signature!");
            }
            return validationResult;
        } catch (IOException ex) {
            throw new SignatureValidationException("Cannot read files!");
        }
    }

    /**
     * Validates timestamp
     */
    private TimeStampTokenInfo validateTimeStamp(Collection timestampSigners, TimeStampToken tsToken) throws CertificateVerificationException {
        try {
            Iterator tstIt = timestampSigners.iterator();
            while (tstIt.hasNext()) {
                SignerInformation tstSignerInformation = (SignerInformation) tstIt.next();
                Store tstCerts = tsToken.getCertificates();
                Iterator tstcertIt = tstCerts.getMatches(tstSignerInformation.getSID()).iterator();
                X509CertificateHolder tstCert = (X509CertificateHolder) tstcertIt.next();
                if (tstcertIt.hasNext()) {
                    throw new Exception("Expected exactly one certificate for each signer in the timestamp.");
                }
                SignerInformationVerifier verifier = new BcRSASignerInfoVerifierBuilder(
                        new DefaultCMSSignatureAlgorithmNameGenerator(),
                        new DefaultSignatureAlgorithmIdentifierFinder(),
                        new DefaultDigestAlgorithmIdentifierFinder(),
                        new BcDigestCalculatorProvider()).build(tstCert);
                tsToken.validate(verifier);
            }
            return tsToken.getTimeStampInfo();
        } catch (Exception ex) {
            log.log(Level.SEVERE, "Error occured while validating timestamp!", ex);
            throw new CertificateVerificationException("Could not validate timestamp..");
        }
    }
}
