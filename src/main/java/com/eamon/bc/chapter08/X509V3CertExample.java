package com.eamon.bc.chapter08;

import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * @author: eamon
 * @date: 2019-02-11 11:21
 * @description:
 */
public class X509V3CertExample {

    public static void main(String[] args) {
        try {
            X509CertificateHolder holder = createCertificateForSigningTimestamps();
            System.out.println(holder.getSubject().toString());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (CertIOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 创建 用于签署时间戳的证书
     *
     * @return
     */
    public static X509CertificateHolder createCertificateForSigningTimestamps() throws NoSuchAlgorithmException,
            OperatorCreationException, CertIOException {
        KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        KeyPair keyPair = pairGenerator.generateKeyPair();

        KeyPair signerKeyPair = KeyPairGenerator.getInstance("RSA",
                new BouncyCastleProvider()).generateKeyPair();

        X509CertificateHolder signerCert = Utils.createTrustAnchor(signerKeyPair, "SHA256WithRSA");

        return Utils.createSpecialPurposeEndEntity(signerCert, signerKeyPair.getPrivate(), "SHA256WithRSA",
                keyPair.getPublic(), KeyPurposeId.id_kp_timeStamping);
    }
}
