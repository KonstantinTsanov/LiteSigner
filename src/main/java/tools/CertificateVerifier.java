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
package tools;

import exceptions.CertificateVerificationException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Objects;
import java.util.ResourceBundle;
import java.util.Set;

/**
 * Verifies a certificate by building a certificate chain and verifying the
 * certificate against CRL
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public class CertificateVerifier {

    private static final CertificateVerifier singleton = new CertificateVerifier();

    public static CertificateVerifier getInstance() {
        return singleton;
    }

    /**
     * Performs certificate validation.
     *
     * @param certificate
     * @param status
     * @return
     * @throws CertificateVerificationException
     *
     * @author Konstantin Tsanov <k.tsanov@gmail.com>
     * @author Svetlin Nakov
     */
    public PKIXCertPathBuilderResult validateCertificate(X509Certificate certificate,
            VerifyingSignatureStatus status) 
            throws CertificateVerificationException {
        ResourceBundle rb = ResourceBundle.getBundle("CoreBundle");
        try {
            if (isSelfSigned(certificate) == true) {
                throw new CertificateVerificationException(rb.getString("certificateVerifier.noCertificateChain"));
            }

            // Prepare a set of trusted root CA certificates
            // and a set of intermediate certificates
            Set<X509Certificate> trustedRootCerts = new HashSet<>();
            Set<X509Certificate> intermediateCerts = new HashSet<>();
            for (X509Certificate additionalCert : Truststore.getInstance().ReadContent()) {
                if (isSelfSigned(additionalCert)) {
                    trustedRootCerts.add(additionalCert);
                } else {
                    intermediateCerts.add(additionalCert);
                }
            }

            // Attempt to build the certification chain and verify it
            PKIXCertPathBuilderResult verifiedCertChain = verifyCertificateChain(
                    certificate, trustedRootCerts, intermediateCerts);

            // Check whether the certificate is revoked by the CRL
            // given in its CRL distribution point extension
            CRLVerifier.getInstance().verifyCertificateCRLs(certificate);
            // The chain is built and verified. Return it as a result
            return verifiedCertChain;
        } catch (CertPathBuilderException certPathEx) {
            status.includeStatus(rb.getString("certificateVerifier.errorBuildingCertificationPath") + certificate.getSubjectX500Principal());
            throw new CertificateVerificationException(
                    rb.getString("certificateVerifier.errorBuildingCertificationPath") + certificate.getSubjectX500Principal(), certPathEx);
        } catch (CertificateVerificationException cvex) {
            status.includeStatus(cvex.getLocalizedMessage());
            throw cvex;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | CertificateException ex) {
            status.includeStatus(rb.getString("certificateVerifier.errorCheckingSelfSigned") + certificate.getSubjectX500Principal());
            throw new CertificateVerificationException(
                    rb.getString("certificateVerifier.errorCheckingSelfSigned") + certificate.getSubjectX500Principal(), ex
            );
        } catch (GeneralSecurityException ex) {
            rb.getString(rb.getString("certificateVerifier.errorVerifyingCertificate") + certificate.getSubjectX500Principal());
            throw new CertificateVerificationException(
                    rb.getString("certificateVerifier.errorVerifyingCertificate") + certificate.getSubjectX500Principal(), ex);
        }
    }

    /**
     * Checks if a certificate is self-signed
     *
     * @param certificate to be checked
     * @return true if the certificate is self signed, false otherwise
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    private boolean isSelfSigned(X509Certificate certificate) throws 
            CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
        Objects.requireNonNull(certificate);
        PublicKey key = certificate.getPublicKey();
        try {
            certificate.verify(key);
            return true;
        } catch (InvalidKeyException | SignatureException ex) {
            return false;
        }
    }

    /**
     * Attempts to build a certification chain for given certificate and to
     * verify it. Relies on a set of root CA certificates (trust anchors) and a
     * set of intermediate certificates (to be used as part of the chain).
     *
     * @param certificate - certificate for validation
     * @param trustedRootCertificates - set of trusted root CA certificates
     * @param intermediateCertificates - set of intermediate certificates
     * @return the certification chain (if verification is successful) (e.g.
     * certification path cannot be built or some certificate in the chain is
     * expired)
     * @author Svetlin Nakov
     */
    private PKIXCertPathBuilderResult verifyCertificateChain(
            X509Certificate certificate, Set<X509Certificate> trustedRootCertificates,
            Set<X509Certificate> intermediateCertificates) throws
            GeneralSecurityException {

        // Create the selector that specifies the starting certificate
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(certificate);

        // Create the trust anchors (set of root CA certificates)
        Set<TrustAnchor> trustAnchors = new HashSet<>();
        trustedRootCertificates.forEach((trustedRootCert) -> {
            trustAnchors.add(new TrustAnchor(trustedRootCert, null));
        });

        // Configure the PKIX certificate builder algorithm parameters
        PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(
                trustAnchors, selector);

        // Disable CRL checks (this is done manually as additional step)
        pkixParams.setRevocationEnabled(false);

        // Specify a list of intermediate certificates
        CertStore intermediateCertStore = CertStore.getInstance("Collection",
                new CollectionCertStoreParameters(intermediateCertificates));
        pkixParams.addCertStore(intermediateCertStore);

        // Build and verify the certification chain
        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
        PKIXCertPathBuilderResult result = (PKIXCertPathBuilderResult) builder
                .build(pkixParams);
        return result;
    }
}
