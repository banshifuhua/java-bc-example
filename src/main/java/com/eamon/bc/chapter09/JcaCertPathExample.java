package com.eamon.bc.chapter09;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static com.eamon.bc.chapter08.Utils.*;
import static com.eamon.bc.chapter09.Utils.createCRL;

/**
 * @author: eamon
 * @date: 2019-02-12 09:10
 * @description: Basic example of certificate path validation using a CertPathValidator.
 */
public class JcaCertPathExample {

    public static void main(String[] args) {
        try {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
            JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter()
                    .setProvider(new BouncyCastleProvider());
            JcaX509CRLConverter crlConverter = new JcaX509CRLConverter().setProvider(new BouncyCastleProvider());

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

            X509CRL trustCRL = crlConverter.getCRL(createEmptyCRL(trustKp.getPrivate(), "SHA256withECDSA", trustHldr));
            X509CRL caCRL = crlConverter.getCRL(createEmptyCRL(caKp.getPrivate(), "SHA256withECDSA", caHldr));

            List<X509Extension> certStoreList = new ArrayList<>();
            certStoreList.add(trustCRL);
            certStoreList.add(caCert);
            certStoreList.add(caCRL);
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

            List<X509Certificate> chain = new ArrayList<>();
            chain.add(caCert);
            chain.add(eeCert);

            CertificateFactory certFact = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
            CertPath certPath = certFact.generateCertPath(chain);

            CertPathValidator validator = CertPathValidator.getInstance("PKIX", new BouncyCastleProvider());
            try {
                PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) validator.validate(certPath, param);

                System.out.println("validated: " + result.getPublicKey());
            } catch (CertPathValidatorException e) {
                e.printStackTrace();
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
        } catch (CRLException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static X509CRLHolder createEmptyCRL(PrivateKey privateKey, String signAlg, X509CertificateHolder trustHldr) throws NoSuchAlgorithmException, OperatorCreationException, IOException {

        return createCRL(privateKey,signAlg,trustHldr,trustHldr);
    }
}
