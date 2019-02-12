package com.eamon.bc.chapter09;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static com.eamon.bc.chapter08.Utils.*;

/**
 * @author: eamon
 * @date: 2019-02-12 10:13
 * @description: Basic example of certificate path validation using a PKIXCertPathChecker with the checker
 * being used for checking revocation status.
 */
public class JcaCertPathWithCheckerExample {

    public static void main(String[] args) {
        try {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
            JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider());

            KeyPair trustKp = kpGen.generateKeyPair();

            X509CertificateHolder trustHldr = createTrustAnchor(trustKp, "SHA256withECDSA");
            X509Certificate trustCert = certConverter.getCertificate(trustHldr);

            KeyPair caKp = kpGen.generateKeyPair();
            X509CertificateHolder caHldr = createIntermediateCertificate(trustHldr, trustKp.getPrivate(),
                    "SHA256withECDSA", caKp.getPublic(), 0);
            X509Certificate caCert = certConverter.getCertificate(caHldr);
            KeyPair eeKp = kpGen.generateKeyPair();
            X509Certificate eeCert = certConverter.getCertificate(createEndEntity(caHldr,
                    caKp.getPrivate(), "SHA256withECDSA", eeKp.getPublic()));
            List certStoreList = new ArrayList();
            certStoreList.add(caCert);
            certStoreList.add(eeCert);
            CollectionCertStoreParameters params = new CollectionCertStoreParameters(certStoreList);
            CertStore certStore = CertStore.getInstance("Collection", params, new BouncyCastleProvider());

            Set<TrustAnchor> trust = new HashSet<>();
            trust.add(new TrustAnchor(trustCert,null));
            X509CertSelector certSelector = new X509CertSelector();
            certSelector.setCertificate(eeCert);

            PKIXParameters param = new PKIXParameters(trust);
            param.setTargetCertConstraints(certSelector);
            param.addCertStore(certStore);
            param.setRevocationEnabled(true);
            param.addCertPathChecker(new OCSPPathChecker(trustKp,trustCert,caCert.getSerialNumber().add(BigInteger.ONE)));
            param.addCertPathChecker(new OCSPPathChecker(caKp,caCert,eeCert.getSerialNumber().add(BigInteger.ONE)));

            CertificateFactory certFact = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());

            List<X509Certificate> chain = new ArrayList<>();
            chain.add(caCert);
            chain.add(eeCert);
            CertPath certPath = certFact.generateCertPath(chain);

            CertPathValidator validator = CertPathValidator.getInstance("PKIX", new BouncyCastleProvider());

            try {
                PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) validator.validate(certPath, param);

                System.out.println("validated: " + result.getPublicKey());
            } catch (CertPathValidatorException e) {
                System.out.println("validation failed: index ("+ e.getIndex() + "), reason \"" + e.getMessage() + "\"");
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (CertIOException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }
}
