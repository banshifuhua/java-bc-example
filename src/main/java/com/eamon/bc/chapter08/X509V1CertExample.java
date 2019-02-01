package com.eamon.bc.chapter08;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * @author: eamon
 * @date: 2019-02-01 09:19
 * @description:
 */
public class X509V1CertExample {
    public static void main(String[] args) throws NoSuchAlgorithmException, OperatorCreationException, IOException, CertificateException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        X509CertificateHolder x509CertificateHolder = Utils.createTrustAnchor(keyPair, "SHA256WithECDSA");
        // x509CertificateHolder 转 标准的 X509Certificate
        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider())
                .getCertificate(x509CertificateHolder);

        // 标准的 X509Certificate 转 x509CertificateHolder
        X509CertificateHolder jcaX509CertificateHolder = new JcaX509CertificateHolder(certificate);

        System.out.println(jcaX509CertificateHolder.getSubject());
        System.out.println(Base64.toBase64String(x509CertificateHolder.getEncoded()));
        System.out.println(certificate.getSubjectDN().toString());
    }
}
