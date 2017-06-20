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
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

/**
 *
 * @author Konstantin Tsanov <k.tsanov@gmail.com>
 * @author Svetlin Nakov
 */
public class CRLVerifier {

    private static CRLVerifier singleton = new CRLVerifier();

    public static CRLVerifier getInstance() {
        return singleton;
    }

    public void verifyCertificateCRLs(X509Certificate cert) throws CertificateVerificationException {
        try {
            List<String> crlDistPoints = getCrlDistributionPoints(cert);
            for (String crlDP : crlDistPoints) {
                X509CRL crl = downloadCRL(crlDP);
                if (crl.isRevoked(cert)) {
                    throw new CertificateVerificationException(
                            "The certificate is revoked by CRL: " + crlDP);
                }
            }
        } catch (Exception ex) {
            if (ex instanceof CertificateVerificationException) {
                throw (CertificateVerificationException) ex;
            } else {
                throw new CertificateVerificationException(
                        "Can not verify CRL for certificate: "
                        + cert.getSubjectX500Principal());
            }
        }
    }

    /**
     * Downloads CRL from given URL. Supports http, https, ftp and ldap based
     * URLs.
     *
     * @author Svetlin Nakov
     */
    private X509CRL downloadCRL(String crlURL) throws IOException,
            CertificateVerificationException, NamingException, MalformedURLException, CertificateException, CRLException {
        if (crlURL.startsWith("http://") || crlURL.startsWith("https://")
                || crlURL.startsWith("ftp://")) {
            return downloadCRLFromWeb(crlURL);
        } else if (crlURL.startsWith("ldap://")) {
            return downloadCRLFromLDAP(crlURL);
        } else {
            throw new CertificateVerificationException(
                    "Can not download CRL from certificate "
                    + "distribution point: " + crlURL);
        }
    }

    /**
     * Downloads a CRL from given LDAP url, e.g.
     * ldap://ldap.infonotary.com/dc=identity-ca,dc=infonotary,dc=com
     *
     * @author Svetlin Nakov
     */
    private X509CRL downloadCRLFromLDAP(String ldapURL) throws CertificateException,
            NamingException, CRLException,
            CertificateVerificationException {
        Map<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY,
                "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapURL);

        DirContext ctx = new InitialDirContext((Hashtable) env);
        Attributes avals = ctx.getAttributes("");
        Attribute aval = avals.get("certificateRevocationList;binary");
        byte[] val = (byte[]) aval.get();
        if ((val == null) || (val.length == 0)) {
            throw new CertificateVerificationException(
                    "Can not download CRL from: " + ldapURL);
        } else {
            InputStream inStream = new ByteArrayInputStream(val);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509CRL) cf.generateCRL(inStream);
        }
    }

    /**
     * Downloads a CRL from given HTTP/HTTPS/FTP URL, e.g.
     * http://crl.infonotary.com/crl/identity-ca.crl
     *
     * @author Svetlin Nakov
     */
    private X509CRL downloadCRLFromWeb(String crlURL) throws MalformedURLException,
            IOException, CertificateException,
            CRLException {
        URL url = new URL(crlURL);
        try (InputStream crlStream = url.openStream()) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509CRL) cf.generateCRL(crlStream);
        }
    }

    /**
     * Extracts all CRL distribution point URLs from the "CRL Distribution
     * Point" extension in a X.509 certificate. If CRL distribution point
     * extension is unavailable, returns an empty list.
     *
     * @param certificate
     * @return
     * @throws java.security.cert.CertificateParsingException
     * @throws java.io.IOException
     * @throws java.security.cert.CertificateEncodingException
     * @author Konstantin Tsanov
     */
    public List<String> getCrlDistributionPoints(X509Certificate certificate) throws CertificateParsingException, IOException, CertificateEncodingException, CertificateException {
        List<String> urlList = new ArrayList<>();
        byte[] crldpExt = certificate.getExtensionValue("2.5.29.31");
        if (crldpExt == null) {
            return urlList;
        }
        try {
            byte[] octedBytes = ((ASN1OctetString) ASN1Primitive.fromByteArray(crldpExt)).getOctets();
            CRLDistPoint distPoint = CRLDistPoint.getInstance(ASN1Primitive.fromByteArray(octedBytes));
            DistributionPoint[] points = distPoint.getDistributionPoints();
            for (DistributionPoint point : points) {
                DistributionPointName distributionPointName = point.getDistributionPoint();
                if (distributionPointName != null) {
                    if (distributionPointName.getType() == DistributionPointName.FULL_NAME) {
                        GeneralNames generalNames = (GeneralNames) distributionPointName.getName();
                        for (GeneralName generalName : generalNames.getNames()) {
                            urlList.add(((ASN1String) generalName.getName()).getString());
                        }
                    }
                }
            }
        } catch (Exception e) {
            //TODO
        }
        return (urlList);
    }

}
