package com.eamon.bc.chapter09;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.Arrays;
import java.util.Date;

import static com.eamon.bc.chapter08.Utils.calculateDate;

/**
 * @author: eamon
 * @date: 2019-02-11 15:52
 * @description:
 */
public class Utils {


    /**
     * Create a CRL containing a single revocation.
     * 创建包含单个吊销的CRL。
     *
     * @param caKey        the private key signing the CRL
     * @param signAlg      the signature algorithm to sign the CRL with
     * @param caCert       the certificate associated with the key signing the CRL
     * @param certToRevoke the certificate to be revoked.
     * @return an X509CRLHolder representing the revocation list for the CA.
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws OperatorCreationException
     */
    public static X509CRLHolder createCRL(PrivateKey caKey, String signAlg,
                                          X509CertificateHolder caCert, X509CertificateHolder certToRevoke)
            throws IOException, NoSuchAlgorithmException, OperatorCreationException {
        X509v2CRLBuilder crlGen = new X509v2CRLBuilder(caCert.getSubject(),
                calculateDate(0));
        crlGen.setNextUpdate(calculateDate(24 * 7));

        // add revocation
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        CRLReason crlReason = CRLReason.lookup(CRLReason.privilegeWithdrawn);

        extGen.addExtension(Extension.reasonCode, false, crlReason);

        crlGen.addCRLEntry(certToRevoke.getSerialNumber(), new Date(), extGen.generate());

        // add extensions to CRL
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

        crlGen.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert));

        ContentSigner contentSigner = new JcaContentSignerBuilder(signAlg)
                .setProvider(new BouncyCastleProvider())
                .build(caKey);

        return crlGen.build(contentSigner);
    }

    /**
     * Simple method to convert an X509CRLHolder to an X509CRL using the java.security.cert.CertificateFactory class.
     *
     * @param crlHolder 待转换 crl
     * @return
     * @throws CertificateException
     * @throws IOException
     */
    public static X509CRL convertX509CRLHolder(X509CRLHolder crlHolder) throws CertificateException, IOException,
            CRLException {
        CertificateFactory cFact = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
        return (X509CRL) cFact.generateCRL(new ByteArrayInputStream(crlHolder.getEncoded()));
    }

    /**
     * Create an updated CRL from a previous one and add a new revocation.
     *
     * @param caKey         the private key signing the CRL.
     * @param signAlg       the signature algorithm to sign the CRL with
     * @param caCert        the certificate associated with the key signing the CRL.
     * @param previousCaCRL the previous CRL for this CA
     * @param certToRevoke  the certificate to be revoked
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws OperatorCreationException
     */
    public static X509CRLHolder updateCRL(PrivateKey caKey, String signAlg, X509CertificateHolder caCert,
                                          X509CRLHolder previousCaCRL, X509CertificateHolder certToRevoke) throws IOException, NoSuchAlgorithmException, OperatorCreationException {

        X509v2CRLBuilder crlGen = new X509v2CRLBuilder(caCert.getSubject(), calculateDate(0));
        crlGen.setNextUpdate(calculateDate(24 * 7));

        // add new revocation
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        CRLReason crlReason = CRLReason.lookup(CRLReason.privilegeWithdrawn);
        extGen.addExtension(Extension.reasonCode, false, crlReason);
        crlGen.addCRLEntry(certToRevoke.getSerialNumber(), new Date(), extGen.generate());

        // add previous revocations
        // 将previousCaCRL中包含的所有条目添加到我们当前使用的CRL构建器中
        crlGen.addCRL(previousCaCRL);
        // add extensions to CRL
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        crlGen.addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(caCert));
        ContentSigner signer = new JcaContentSignerBuilder(signAlg)
                .setProvider(new BouncyCastleProvider())
                .build(caKey);

        return crlGen.build(signer);
    }

    /**
     * Generation of an OCSP request concerning certificate serialNumber from
     * issuer represented by issuerCert with a nonce extension.
     * 生成ocsp请求
     *
     * @param issuerCert   certificate of issuer of certificate we want to check.
     * @param serialNumber serial number of the certificate we want to check
     * @return an OCSP request
     * @throws OperatorCreationException
     * @throws OCSPException
     */
    public static OCSPReq generateOCSPRequest(X509CertificateHolder issuerCert, BigInteger serialNumber)
            throws OperatorCreationException, OCSPException {

        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder()
                .setProvider(new BouncyCastleProvider())
                .build();

        // Generate the id for the certificate we are looking for
        CertificateID id = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), issuerCert, serialNumber);

        // basic request generation with nonce
        OCSPReqBuilder bldr = new OCSPReqBuilder();
        bldr.addRequest(id);
        BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
        bldr.setRequestExtensions(new Extensions(new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, true,
                new DEROctetString(nonce.toByteArray()))));
        return bldr.build();
    }

    /**
     * Generation of an OCSP response based on a single revoked certificate.
     *
     * @param request             the OCSP request we are asked to check.
     * @param responderKey        signing key for the responder.
     * @param pubKey              public key for responder.
     * @param revokedSerialNumber the serial number that we regard as revoked.
     * @return an OCSP response.
     * @throws OperatorCreationException
     * @throws OCSPException
     */
    public static OCSPResp generateOCSPResponse(OCSPReq request, PrivateKey responderKey, SubjectPublicKeyInfo pubKey,
                                                BigInteger revokedSerialNumber) throws OperatorCreationException, OCSPException {
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder()
                .setProvider(new BouncyCastleProvider())
                .build();

        BasicOCSPRespBuilder basicRespBldr = new BasicOCSPRespBuilder(pubKey, digCalcProv.get(CertificateID.HASH_SHA1));
        Extension ext = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (ext != null) {
            basicRespBldr.setResponseExtensions(new Extensions(ext));
        }
        Req[] requests = request.getRequestList();
        for (Req req : requests) {
            CertificateID certID = req.getCertID();
            // this would normally be a lot more general!
            if (certID.getSerialNumber().equals(revokedSerialNumber)) {
                basicRespBldr.addResponse(certID, new RevokedStatus(new Date(), CRLReason.privilegeWithdrawn));
            } else {
                basicRespBldr.addResponse(certID, CertificateStatus.GOOD);
            }
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WITHECDSA")
                .setProvider(new BouncyCastleProvider())
                .build(responderKey);
        BasicOCSPResp basicResp = basicRespBldr.build(signer, null, new Date());
        OCSPRespBuilder ocspRespBuilder = new OCSPRespBuilder();
        return ocspRespBuilder.build(OCSPRespBuilder.SUCCESSFUL, basicResp);
    }

    /**
     * Check a certificate against a revoked serial number by using an OCSP request and response
     * 使用OCSP请求和响应检查证书以查找已撤销的序列号
     *
     * @param caPrivKey           the issuer private key.
     * @param caCert              the issuer certificate.
     * @param revokedSerialNumber a serial number the responder is to treat as revoked.
     * @param certToCheck         the certificate to generate the OCSP request for.
     * @return a status message for certToCheck
     * @throws OCSPException
     * @throws OperatorCreationException
     * @throws IOException
     */
    public static String getStatusMessage(PrivateKey caPrivKey, X509CertificateHolder caCert,
                                          BigInteger revokedSerialNumber, X509CertificateHolder certToCheck)
            throws OCSPException, OperatorCreationException, IOException {
        OCSPReq request = generateOCSPRequest(caCert, certToCheck.getSerialNumber());

        OCSPResp response = generateOCSPResponse(request, caPrivKey, certToCheck.getSubjectPublicKeyInfo(),
                revokedSerialNumber);

        BasicOCSPResp basicOCSPResp = (BasicOCSPResp) response.getResponseObject();

        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
                .setProvider(new BouncyCastleProvider())
                .build(caCert.getSubjectPublicKeyInfo());

        // verify the response
        if (basicOCSPResp.isSignatureValid(verifier)) {
            SingleResp[] responses = basicOCSPResp.getResponses();

            Extension reqNonceExt = request.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            byte[] reqNonce = reqNonceExt.getEncoded();
            Extension respNonceExt = basicOCSPResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            // validate the nonce if it is present
            if (respNonceExt != null && Arrays.equals(reqNonce, respNonceExt.getEncoded())) {
                StringBuilder message = new StringBuilder();
                for (SingleResp respons : responses) {
                    message.append(" certificate number ").append(respons.getCertID().getSerialNumber());
                    if (respons.getCertStatus() == CertificateStatus.GOOD) {
                        return message.append(" status: good").toString();
                    } else {
                        return message.append(" status: revoked").toString();
                    }
                }
                return message.toString();
            } else {
                return "response nonce failed to validate";
            }
        } else {
            return "response failed to verify";
        }


    }
}
