/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
import java.util.Set;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 */
public class CertificateVerifier {

    private static final CertificateVerifier singleton = new CertificateVerifier();

    public static CertificateVerifier getInstance() {
        return singleton;
    }

    /**
     *
     * @param certificate
     * @return
     * @throws CertificateVerificationException
     *
     * @author Konstantin Tsanov <k.tsanov@gmail.com>
     * @author Svetlin Nakov
     */
    public PKIXCertPathBuilderResult validateCertificate(X509Certificate certificate) throws
            CertificateVerificationException {
        try {
            if (isSelfSigned(certificate) == true) {
                throw new CertificateVerificationException("There's no certificate chain for the certificate!");
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
            PKIXCertPathBuilderResult verifiedCertChain = verifyCertificate(
                    certificate, trustedRootCerts, intermediateCerts);

            // Check whether the certificate is revoked by the CRL
            // given in its CRL distribution point extension
            CRLVerifier.getInstance().verifyCertificateCRLs(certificate);
            // The chain is built and verified. Return it as a result
            return verifiedCertChain;
        } catch (CertPathBuilderException certPathEx) {
            throw new CertificateVerificationException(
                    "Error building certification path: "
                    + certificate.getSubjectX500Principal(), certPathEx);
        } catch (CertificateVerificationException cvex) {
            throw cvex;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | CertificateException ex) {
            throw new CertificateVerificationException(
                    "Error checking for selfSigned: "
                    + certificate.getSubjectX500Principal(), ex);
        } catch (GeneralSecurityException ex) {
            throw new CertificateVerificationException(
                    "Error verifying the certificate: "
                    + certificate.getSubjectX500Principal(), ex);
        }
    }

    private boolean isSelfSigned(X509Certificate certificate) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
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
    private PKIXCertPathBuilderResult verifyCertificate(
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
