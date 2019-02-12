package com.eamon.bc.chapter09;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import static com.eamon.bc.chapter08.Utils.createIntermediateCertificate;
import static com.eamon.bc.chapter08.Utils.createTrustAnchor;
import static com.eamon.bc.chapter09.Utils.getStatusMessage;

/**
 * @author: eamon
 * @date: 2019-02-11 17:25
 * @description:
 */
public class OcspExample {
    public static void main(String[] args) throws NoSuchAlgorithmException, OperatorCreationException, IOException, OCSPException {
        KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        KeyPair caKp = pairGenerator.generateKeyPair();

        X509CertificateHolder caCert = createTrustAnchor(caKp, "SHA256withECDSA");

        KeyPair certKp = pairGenerator.generateKeyPair();

        X509CertificateHolder certOfInterest = createIntermediateCertificate(caCert, caKp.getPrivate(),
                "SHA256withECDSA", certKp.getPublic(), 0);


        // 错误的序列号 返回 good
        System.out.println(getStatusMessage(caKp.getPrivate(), caCert,
                certOfInterest.getSerialNumber().add(BigInteger.ONE), certOfInterest));

        // 正确的 证书序列号 返回 revoked
        System.out.println(getStatusMessage(caKp.getPrivate(), caCert,
                certOfInterest.getSerialNumber(), certOfInterest));
    }
}
