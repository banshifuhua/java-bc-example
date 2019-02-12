package com.eamon.bc.chapter10;

import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.crmf.SubsequentMessage;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;

/**
 * @author: eamon
 * @date: 2019-02-12 13:15
 * @description:
 */
public class Utils {


    /**
     * Create a basic PKCS#10 request
     *
     * @param keyPair the key pair the certification request is for.
     * @param sigAlg  the signature algorithm to sign the PKCS#10 request with.
     * @return an object carrying the PKCS#10 request.
     */
    public static PKCS10CertificationRequest createPKCS10(KeyPair keyPair, String sigAlg) throws OperatorCreationException {
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "AU")
                .addRDN(BCStyle.ST, "Victoria")
                .addRDN(BCStyle.L, "Melbourne")
                .addRDN(BCStyle.O, "The Legion of the Bouncy Castle");
        X500Name subject = x500NameBld.build();
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider(new BouncyCastleProvider())
                .build(keyPair.getPrivate());
        JcaPKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(subject,
                keyPair.getPublic());
        return requestBuilder.build(signer);
    }

    /**
     * Simple method to check the signature on a PKCS#10 certification test with a public key.
     *
     * @param request the encoding of the PKCS#10 request of interest
     * @return true if the public key verifies the signature, false otherwise
     * @throws OperatorCreationException in case the public key is unsuitable
     * @throws PKCSException             if the PKCS#10 request cannot be processed.
     * @throws GeneralSecurityException
     * @throws NoSuchAlgorithmException
     */
    public static boolean isValidPKCS10Request(byte[] request)
            throws OperatorCreationException, PKCSException, GeneralSecurityException, IOException {
        JcaPKCS10CertificationRequest jcaRequest = new JcaPKCS10CertificationRequest(request)
                .setProvider(new BouncyCastleProvider());
        PublicKey key = jcaRequest.getPublicKey();
        ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
                .setProvider(new BouncyCastleProvider())
                .build(key);
        return jcaRequest.isSignatureValid(verifierProvider);

    }

    /**
     * Create a PKCS#10 request including an extension request detailing the
     * email address the CA should include in the subjectAltName extension.
     * 创建一个PKCS＃10请求，其中包含详细说明CA应包含在subjectAltName扩展名中的电子邮件地址的扩展请求。
     *
     * @param keyPair the key pair the certification request is for.
     * @param sigAlg  the signature algorithm to sign the PKCS#10 request with.
     * @return an object carrying the PKCS#10 request.
     * @throws IOException               on an ASN.1 encoding error.
     * @throws OperatorCreationException in case the private key is inappropriate for signature algorithm selected.
     */
    public static PKCS10CertificationRequest createPKCS10WithExtensions(KeyPair keyPair, String sigAlg)
            throws IOException, OperatorCreationException {
        X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "AU")
                .addRDN(BCStyle.ST, "Victoria")
                .addRDN(BCStyle.L, "Melbourne")
                .addRDN(BCStyle.O, "The Legion of the Bouncy Castle");
        X500Name subject = x500NameBld.build();

        JcaPKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(subject,
                keyPair.getPublic());

        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.rfc822Name, "feedback-crypto@bouncycastle.org")));
        Extensions extensions = extGen.generate();
        requestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions);
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider(new BouncyCastleProvider())
                .build(keyPair.getPrivate());
        return requestBuilder.build(signer);
    }

    /**
     * Basic example for generating a CRMF certificate request with POP for
     * an signing algorithm like DSA or a key pair for signature generation
     * from an algorithm like RSA.
     *
     * @param kp        key pair whose public key we are making the request for.
     * @param subject   subject principal to be associated with the certificate
     * @param certReqID identity (for the client) of this certificate request
     * @return
     * @throws CRMFException
     * @throws IOException
     * @throws OperatorCreationException
     */
    public static byte[] generateRequestWithPOPSig(KeyPair kp, X500Principal subject, BigInteger certReqID)
            throws CRMFException, IOException, OperatorCreationException {
        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(certReqID);
        certReqBuild.setSubject(subject)
                .setPublicKey(kp.getPublic())
                .setProofOfPossessionSigningKeySigner(
                        new JcaContentSignerBuilder("SHA256withRSA")
                                .setProvider(new BouncyCastleProvider())
                                .build(kp.getPrivate()));
        return certReqBuild.build().getEncoded();
    }

    /**
     * Authenticating example for generating a CRMF certificate request with POP
     * for a signing algorithm. In this case the CA will verify the subject from
     * the MAC validation.
     * 验证使用POP为签名算法生成CRMF证书请求的示例。 在这种情况下，CA将通过MAC验证来验证主题。
     *
     * @param kp          key pair whose public key we are making the request for.
     * @param certReqID   identity (for the client) of this certificate request
     * @param reqPassword authorising password for this request.
     * @return
     * @throws OperatorCreationException
     * @throws CRMFException
     * @throws IOException
     */
    public static byte[] generateRequestWithPOPSig(KeyPair kp, BigInteger certReqID, char[] reqPassword)
            throws OperatorCreationException, CRMFException, IOException {
        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(certReqID);
        certReqBuild.setPublicKey(kp.getPublic())
                .setAuthInfoPKMAC(new PKMACBuilder(new JcePKMACValuesCalculator()), reqPassword)
                .setProofOfPossessionSigningKeySigner(
                        new JcaContentSignerBuilder("SHA256withRSA")
                                .setProvider(new BouncyCastleProvider())
                                .build(kp.getPrivate()));
        return certReqBuild.build().getEncoded();
    }

    /**
     * Basic example for generating a CRMF certificate request with POP for
     * an encryption only algorithm like ElGamal.
     * 使用POP为仅加密算法（如ElGamal）生成CRMF证书请求的基本示例。
     *
     * @param kp        key pair whose public key we are making the request for.
     * @param subject   subject principal to be associated with the certificate
     * @param certReqID identity (for the client) of this certificate request
     * @return
     * @throws CRMFException
     * @throws IOException
     */
    public static byte[] generateRequestWithPOPEnc(KeyPair kp, X500Principal subject, BigInteger certReqID)
            throws CRMFException, IOException {
        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(certReqID);
        certReqBuild.setPublicKey(kp.getPublic())
                .setSubject(subject)
                .setProofOfPossessionSubsequentMessage(SubsequentMessage.encrCert);
        return certReqBuild.build().getEncoded();
    }

    /**
     * Basic example for generating a CRMF certificate request with POP for
     * a key agreement public key.
     * 使用POP为密钥协商公钥生成CRMF证书请求的基本示例。
     *
     * @param kp
     * @param subject
     * @param certReqID
     * @return
     * @throws CRMFException
     * @throws IOException
     */
    public static byte[] generateRequestWithPOPAgree(KeyPair kp, X500Principal subject, BigInteger certReqID)
            throws CRMFException, IOException {
        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(certReqID);
        certReqBuild.setPublicKey(kp.getPublic())
                .setSubject(subject)
                .setProofOfPossessionSubsequentMessage(ProofOfPossession.TYPE_KEY_AGREEMENT, SubsequentMessage.encrCert);
        return certReqBuild.build().getEncoded();
    }

}
