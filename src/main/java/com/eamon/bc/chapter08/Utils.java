package com.eamon.bc.chapter08;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * @author: eamon
 * @date: 2019-01-31 17:39
 * @description:
 */
public class Utils {

    private static long serialNumberBase = System.currentTimeMillis();

    /**
     * Calculate a date in seconds (suitable for the PKIX profile - RFC 5280)
     *
     * @param hoursInFuture hours ahead of now, may be negative.
     * @return
     */
    public static Date calculateDate(int hoursInFuture) {
        long secs = System.currentTimeMillis() / 1000;
        return new Date((secs + (hoursInFuture * 60 * 60)) * 1000);
    }

    /**
     * Calculate a serial number using a monotonically increasing value
     *
     * @return a BigInteger representing the next serial number in the sequence
     */
    public static BigInteger calculateSerialNumber() {
        return BigInteger.valueOf(serialNumberBase++);
    }


    public static X509CertificateHolder createTrustAnchor(KeyPair keyPair, String sigAlg) throws OperatorCreationException {
        X500Name x500Name = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "CN")
                .addRDN(BCStyle.ST, "Shanghai")
                .addRDN(BCStyle.L, "shanghai")
                .addRDN(BCStyle.O, "TrustAsia")
                .addRDN(BCStyle.CN, "Eamon Zhang")
                .build();
        JcaX509v1CertificateBuilder certificateBuilder = new JcaX509v1CertificateBuilder(x500Name,
                calculateSerialNumber(), calculateDate(0), calculateDate(24 * 31),
                x500Name, keyPair.getPublic());

        ContentSigner contentSigner = new JcaContentSignerBuilder(sigAlg)
                .setProvider(new BouncyCastleProvider())
                .build(keyPair.getPrivate());

        return certificateBuilder.build(contentSigner);

    }

    /**
     * Simple method to convert an X509CertificateHolder to an X509Certificate using
     * the java.security.cert.CertificateFactory class.
     *
     * @param certHolder
     * @return
     * @throws IOException
     * @throws CertificateException
     */
    public static X509Certificate convertX509CertificateHolder(X509CertificateHolder certHolder) throws IOException,
            CertificateException {
        CertificateFactory certFact = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
        return (X509Certificate) certFact.generateCertificate(new ByteArrayInputStream(certHolder.getEncoded()));
    }

    /**
     * Extract the DER encoded value octets of an extension from a JCA X509Certificate.
     *
     * @param certificate
     * @param extensionOID
     * @return
     */
    public static byte[] extractExtensionValue(X509Certificate certificate, ASN1ObjectIdentifier extensionOID) {
        byte[] octString = certificate.getExtensionValue(extensionOID.getId());
        if (octString == null) {
            return null;
        }
        return ASN1OctetString.getInstance(octString).getOctets();
    }

    /**
     * Build a sample V3 intermediate certificate that can be used as a CA certificate.
     * 构建可用作CA证书的示例V3中间证书。
     *
     * @param signerCert       certificate carrying the public key that will later * be used to verify this certificate's signature.
     * @param signerKey        private key used to generate the signature in the
     *                         certificate.
     * @param sigAlg           the signature algorithm to sign the certificate with.
     * @param certKey          public key to be installed in the certificate.
     * @param followingCACerts pathLen
     * @return an X509CertificateHolder containing the V3 certificate.
     * @throws NoSuchAlgorithmException
     * @throws CertIOException
     * @throws OperatorCreationException
     */
    public static X509CertificateHolder createIntermediateCertificate(X509CertificateHolder signerCert,
                                                                      PrivateKey signerKey, String sigAlg,
                                                                      PublicKey certKey, int followingCACerts) throws NoSuchAlgorithmException, CertIOException, OperatorCreationException {
        X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, "Demo Intermediate Certificate")
                .addRDN(BCStyle.C, "CN")
                .addRDN(BCStyle.L, "Shanghai")
                .addRDN(BCStyle.ST, "Shanghai")
                .addRDN(BCStyle.O, "TrustAsia");
        X500Name subject = x500NameBuilder.build();
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(signerCert.getSubject(),
                calculateSerialNumber(), calculateDate(0), calculateDate(24 * 31),
                subject, certKey);
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(signerCert))
                .addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(certKey))
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(followingCACerts))
                .addExtension(Extension.keyUsage, true,
                        new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));
        ContentSigner contentSigner = new JcaContentSignerBuilder(sigAlg)
                .setProvider(new BouncyCastleProvider())
                .build(signerKey);
        return certBuilder.build(contentSigner);
    }

    /**
     * Create a general end-entity certificate for use in verifying digital signatures.
     * 创建用于验证数字签名的通用终端实体证书。
     *
     * @param signerCert certificate carrying the public key that will later be used to verify this certificate's signature.
     * @param signerKey  private key used to generate the signature in the certificate.
     * @param signAlg    the signature algorithm to sign the certificate with
     * @param certKey    public key to be installed in the certificate.
     * @return an X509CertificateHolder containing the V3 certificate
     * @throws CertIOException
     * @throws OperatorCreationException
     * @throws NoSuchAlgorithmException
     */
    public static X509CertificateHolder createEndEntity(X509CertificateHolder signerCert, PrivateKey signerKey,
                                                        String signAlg, PublicKey certKey) throws CertIOException,
            OperatorCreationException, NoSuchAlgorithmException {
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, "Demo End-Entity Certificate")
                .addRDN(BCStyle.C, "CN")
                .addRDN(BCStyle.ST, "Shanghai")
                .addRDN(BCStyle.L, "shanghai")
                .addRDN(BCStyle.O, "Trustasia");

        X500Name subject = x500NameBld.build();

        JcaX509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(signerCert.getSubject(),
                calculateSerialNumber(), calculateDate(0), calculateDate(24 * 31),
                subject, certKey);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        certBldr.addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(signerCert))
                .addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(certKey))
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        ContentSigner contentSigner = new JcaContentSignerBuilder(signAlg)
                .setProvider(new BouncyCastleProvider())
                .build(signerKey);

        return certBldr.build(contentSigner);

    }

    /**
     * Create a special purpose end entity cert which is associated with a particular key purpose.
     * 创建与特定关键用途相关联的特殊用途的最终实体证书。
     *
     * @param signerCert certificate carrying the public key that will later be used to verify this certificate's signature
     * @param signerKey  private key used to generate the signature in the certificate.
     * @param signAlg    the signature algorithm to sign the certificate with
     * @param certKey    public key to be installed in the certificate.
     * @param keyPurpose the specific KeyPurposeId to associate with this certificate's public key.
     * @return an X509CertificateHolder containing the V3 certificate.
     * @throws OperatorCreationException
     * @throws NoSuchAlgorithmException
     * @throws CertIOException
     */
    public static X509CertificateHolder createSpecialPurposeEndEntity(X509CertificateHolder signerCert,
                                                                      PrivateKey signerKey, String signAlg,
                                                                      PublicKey certKey, KeyPurposeId keyPurpose)
            throws OperatorCreationException, NoSuchAlgorithmException, CertIOException {

        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, "Demo End-Entity Certificate")
                .addRDN(BCStyle.C, "CN")
                .addRDN(BCStyle.ST, "Shanghai")
                .addRDN(BCStyle.L, "shanghai")
                .addRDN(BCStyle.O, "Trustasia");

        X500Name subject = x500NameBld.build();

        JcaX509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(signerCert.getSubject(),
                calculateSerialNumber(), calculateDate(0), calculateDate(24 * 31),
                subject, certKey);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certBldr.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(signerCert))
                .addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(certKey))
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                .addExtension(Extension.keyUsage, true, new ExtendedKeyUsage(keyPurpose));

        ContentSigner contentSigner = new JcaContentSignerBuilder(signAlg)
                .setProvider(new BouncyCastleProvider())
                .build(signerKey);

        return certBldr.build(contentSigner);
    }

    /**
     * The following example shows the construction of a simple attribute certificate that just includes a
     * URI for a user’s role using the RoleSyntax defined in RFC 5755
     * 创建 属性证书
     *
     * @param issuerCert
     * @param issuerKey
     * @param sigAlg
     * @param holderCert
     * @param holderRoleUri
     * @return
     * @throws OperatorCreationException
     */
    public static X509AttributeCertificateHolder createAttributeCertificate(X509CertificateHolder issuerCert,
                                                                            PrivateKey issuerKey, String sigAlg,
                                                                            X509CertificateHolder holderCert,
                                                                            String holderRoleUri)
            throws OperatorCreationException {

        X509v2AttributeCertificateBuilder acBldr = new X509v2AttributeCertificateBuilder(
                new AttributeCertificateHolder(holderCert),
                new AttributeCertificateIssuer(issuerCert.getSubject()),
                calculateSerialNumber(),
                calculateDate(0),
                calculateDate(24 * 31));

        GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, holderRoleUri);

        acBldr.addAttribute(X509AttributeIdentifiers.id_at_role, new RoleSyntax(generalName));

        ContentSigner contentSigner = new JcaContentSignerBuilder(sigAlg)
                .setProvider(new BouncyCastleProvider())
                .build(issuerKey);

        return acBldr.build(contentSigner);

    }


}
