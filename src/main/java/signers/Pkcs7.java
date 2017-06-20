/* 
 * The MIT License
 *
 * Copyright 2017 Konstantin Tsanov <k.tsanov@gmail.com>.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package signers;

import enums.SignatureType;
import exceptions.CertificateVerificationException;
import exceptions.SignatureValidationException;
import exceptions.SigningException;
import exceptions.TimestampVerificationException;
import exceptions.TimestampingException;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
import javax.naming.AuthenticationException;
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
import tools.VerifyingSignatureStatus;

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
    private static ResourceBundle rb = loadBundle();

    public Pkcs7() {

    }

    public Pkcs7(Pkcs1_ pkcs1x, String alias, File input, File output, URL timestampAddress) {
        _pkcs1x = pkcs1x;
        _alias = alias;
        _input = input;
        _output = output;
        _timestampAddress = timestampAddress;
    }

    @Override
    public void sign(boolean attached) throws AuthenticationException, SigningException {
        Objects.requireNonNull(_input);
        Objects.requireNonNull(_output);
        Objects.requireNonNull(_alias);
        Security.addProvider(new BouncyCastleProvider());
        try {

            X509Certificate cert;
            cert = (X509Certificate) _pkcs1x.get_certKeyStore().getCertificate(_alias);
            List certList = new ArrayList();
            certList.add(cert);
            Store certs = new JcaCertStore(certList);
            CMSProcessableFile inputFile = new CMSProcessableFile(_input);
            char[] pin = _pkcs1x.get_passwordCallback().getPin();
            if (pin == null) {
                throw new AuthenticationException("No pin input.");
            }
            ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA")
                    .setProvider(_pkcs1x.get_provider()).build((PrivateKey) _pkcs1x.get_certKeyStore()
                    .getKey(_alias, pin));
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
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            log.log(Level.SEVERE, "Failed to sign!", ex);
            throw new SigningException(rb.getString("signingFiled"));
        }
    }

    /**
     * Timestamp request from the server
     *
     * @param data
     * @param uri
     * @return
     * @throws TimestampingException
     */
    private TimeStampResponse timestampRequest(byte[] data, URI uri) throws TimestampingException {
        try {
            TimeStampRequestGenerator tstRequestGenerator = new TimeStampRequestGenerator();
            tstRequestGenerator.setCertReq(true);
            TimeStampRequest req = tstRequestGenerator.generate(TSPAlgorithms.SHA1, data);
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
                throw new IOException(rb.getString("timestampingHttpError") + conn.getResponseCode() + " - " + conn.getResponseMessage());
            }
            InputStream in = conn.getInputStream();
            TimeStampResp resp = TimeStampResp.getInstance(new ASN1InputStream(in).readObject());
            TimeStampResponse response = new TimeStampResponse(resp);
            response.validate(req);
            if (response.getStatus() != 0) {
                throw new IOException(rb.getString("timestampingBadResponseError") + response.getStatusString() + ")");
            }
            return response;
        } catch (Exception ex) {
            throw new TimestampingException(rb.getString("timestampValidationError"), ex);
        }
    }

    @Override
    public String validate(File pkcs7, File signedFile) throws FileNotFoundException,
            SignatureValidationException,
            TimestampVerificationException,
            CertificateVerificationException,
            IOException {
        SignatureType signatureType = checkFileType(pkcs7);
        if (signatureType == SignatureType.Attached) {
            try (InputStream is = new FileInputStream(pkcs7)) {
                return validateAttachedSignature(is).getStatus();
            } catch (IOException ex) {
                throw new FileNotFoundException(rb.getString("pkcs7FileNotFoundException"));
            }
        } else {
            if (signedFile == null) {
                throw new FileNotFoundException(rb.getString("signedFileNotFoundException"));
            }
            return validateDetachedSignature(pkcs7, signedFile).getStatus();
        }
    }

    private VerifyingSignatureStatus validateAttachedSignature(InputStream attached) throws CertificateVerificationException, TimestampVerificationException {
        VerifyingSignatureStatus status = new VerifyingSignatureStatus();
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        try {
            CMSSignedData cmsSignedData = new CMSSignedData(attached);
            SignerInformationStore signers = cmsSignedData.getSignerInfos();
            Collection<SignerInformation> c = signers.getSigners();
            boolean result;
            for (SignerInformation signerInformation : c) {
                SignerId signerId = signerInformation.getSID();
                Collection certCollection = cmsSignedData.getCertificates().getMatches(signerId);

                Iterator certIt = certCollection.iterator();
                X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate((X509CertificateHolder) certIt.next());
                result = signerInformation.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));
                if (!result) {
                    status.includeStatus("status.signatureInvalid");
                    return status;
                }
                CertificateVerifier.getInstance().validateCertificate(cert);
                status.includeStatus(rb.getString("status.certificateValidationPassed"));
                //TIMESTAMP PART
                checkIfTimestampExists(signerInformation, status);
            }
            return status;
        } catch (CertificateException | CMSException | OperatorCreationException | StoreException ex) {
            log.log(Level.SEVERE, "An error occured while validating the signature!", ex);
            throw new CertificateVerificationException(rb.getString("signatureValidationFailedError"), ex);
        }
    }

    private VerifyingSignatureStatus validateDetachedSignature(File pkcs7, File signedFile) throws SignatureValidationException {
        VerifyingSignatureStatus status = new VerifyingSignatureStatus();
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
                    SignerInformation signerInformation = (SignerInformation) it.next();
                    X509CertificateHolder cert = (X509CertificateHolder) certs.getMatches(signerInformation.getSID()).iterator().next();

                    SignerInformationVerifier verifier = new BcRSASignerInfoVerifierBuilder(
                            new DefaultCMSSignatureAlgorithmNameGenerator(),
                            new DefaultSignatureAlgorithmIdentifierFinder(),
                            new DefaultDigestAlgorithmIdentifierFinder(),
                            new BcDigestCalculatorProvider()).build(cert);
                    if (signerInformation.verify(verifier)) {
                        status.includeStatus(rb.getString("status.signatureVerified"));
                    } else {
                        status.includeStatus(rb.getString("status.signatureInvalid"));
                        return status;
                    }
                    checkIfTimestampExists(signerInformation, status);
                }

            } catch (Exception e) {
                throw new SignatureValidationException(rb.getString("signatureValidationFailed"));
            }
            return status;
        } catch (IOException ex) {
            throw new SignatureValidationException(rb.getString("couldNotReadFilesError"));
        }
    }

    /**
     * Checks if the signerInformation contains any unsignedAttributes. If it
     * does, then checks if the unsignedAttributes contain
     * signatureTimeStampToken
     *
     * @param signerInformation - info to be checked.
     * @param status - A string, carrying all data related to the signature
     * validation and timestamp verification
     * @throws TimestampVerificationException - If anything other than the
     * verification failing happens this exception is thrown.
     */
    private void checkIfTimestampExists(SignerInformation signerInformation, VerifyingSignatureStatus status) throws TimestampVerificationException {
        AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
        if (unsignedAttributes != null) {
            Attribute timestampAttribute = unsignedAttributes.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
            if (timestampAttribute == null) {
                status.includeStatus(rb.getString("status.noTimestamp"));
                log.log(Level.FINE, "The signature contains no timestamp.");
            } else {
                try {
                    ASN1Encodable dob = timestampAttribute.getAttrValues().getObjectAt(0);
                    CMSSignedData signedData = new CMSSignedData(dob.toASN1Primitive().getEncoded());
                    TimeStampToken tst = new TimeStampToken(signedData);
                    Collection tstSigners = tst.toCMSSignedData().getSignerInfos().getSigners();
                    TimeStampTokenInfo timestampInfo = validateTimeStamp(tstSigners, tst);
                    status.includeStatus(rb.getString("status.hasTimestamp"));
                    status.includeStatus(String.format("TSA: %s\n Time: %s", timestampInfo.getTsa().toString(), timestampInfo.getGenTime().toString()));
                } catch (CMSException | TSPException | IOException ex) {
                    log.log(Level.SEVERE, "The process of timestamp verification failed!", ex);
                    throw new TimestampVerificationException(rb.getString("timestampValidationError"));
                }
            }
        } else {
            status.includeStatus(rb.getString("status.noTimestamp"));
        }
    }

    /**
     * Validates the timestamp
     *
     * @param timestampSigners
     * @param tsToken
     * @return
     * @throws TimestampVerificationException
     */
    private TimeStampTokenInfo validateTimeStamp(Collection timestampSigners, TimeStampToken tsToken) throws TimestampVerificationException {
        try {
            Iterator tstIt = timestampSigners.iterator();
            while (tstIt.hasNext()) {
                SignerInformation tstSignerInformation = (SignerInformation) tstIt.next();
                Store tstCerts = tsToken.getCertificates();
                Iterator tstcertIt = tstCerts.getMatches(tstSignerInformation.getSID()).iterator();
                X509CertificateHolder tstCert = (X509CertificateHolder) tstcertIt.next();
                if (tstcertIt.hasNext()) {
                    throw new TimestampVerificationException(rb.getString("timestampingCertificateError"));
                }
                SignerInformationVerifier verifier = new BcRSASignerInfoVerifierBuilder(
                        new DefaultCMSSignatureAlgorithmNameGenerator(),
                        new DefaultSignatureAlgorithmIdentifierFinder(),
                        new DefaultDigestAlgorithmIdentifierFinder(),
                        new BcDigestCalculatorProvider()).build(tstCert);
                tsToken.validate(verifier);
            }
            return tsToken.getTimeStampInfo();
        } catch (TimestampVerificationException ex) {
            throw ex;
        } catch (OperatorCreationException | TSPException | StoreException ex) {
            log.log(Level.SEVERE, "Error occured while validating timestamp!", ex);
            throw new TimestampVerificationException(rb.getString("signatureValidationFailedError"), ex);
        }
    }

    /**
     * Checks whether the pkcs7 file contains encapsulated data.
     *
     * @param pkcs7 - input file.
     * @return SignatureType.Attached if the pkcs7 file contains encapsulated
     * data. SignatureType.Detached if the pkcs7 file does not contain
     * encapsulated data.
     */
    private SignatureType checkFileType(File pkcs7) throws IOException, SignatureValidationException {
        byte[] Sig_Bytes = new byte[(int) pkcs7.length()];
        try (DataInputStream in = new DataInputStream(new FileInputStream(pkcs7))) {
            in.readFully(Sig_Bytes);
            in.close();
            CMSSignedData cmsSignedData = new CMSSignedData(Sig_Bytes);
            Object signedData = cmsSignedData.getSignedContent();
            if (signedData == null) {
                return SignatureType.Detached;
            } else {
                return SignatureType.Attached;
            }
        } catch (IOException ex) {
            log.log(Level.SEVERE, "An error occured while reading file!", ex);
            throw new FileNotFoundException(rb.getString("pkcs7FileNotFoundException"));
        } catch (CMSException ex) {
            log.log(Level.SEVERE, "An error occured while constructing the pkcs7 object!", ex);
            throw new SignatureValidationException(rb.getString("pkcs7FileIsNotCorrect"));
        }
    }

    /**
     * Loads the language resource bundle.
     *
     * @return Loaded bundle.
     */
    private static ResourceBundle loadBundle() {
        ResourceBundle r = ResourceBundle.getBundle("CoreBundle");
        return r;
    }
}
