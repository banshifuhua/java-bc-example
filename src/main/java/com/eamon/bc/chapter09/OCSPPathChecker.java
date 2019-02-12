package com.eamon.bc.chapter09;

import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.*;
import java.util.Collection;
import java.util.Set;

/**
 * @author: eamon
 * @date: 2019-02-12 10:06
 * @description: A basic path checker that does an OCSP check for a single CA
 */
public class OCSPPathChecker extends PKIXCertPathChecker {

    private KeyPair responderPair;
    private X509Certificate caCert;
    private BigInteger revokedSerialNumber;

    public OCSPPathChecker(KeyPair responderPair, X509Certificate caCert, BigInteger revokedSerialNumber) {
        this.responderPair = responderPair;
        this.caCert = caCert;
        this.revokedSerialNumber = revokedSerialNumber;
    }

    @Override
    public void init(boolean forward) throws CertPathValidatorException {
        // ignore
    }

    @Override
    public boolean isForwardCheckingSupported() {
        return true;
    }

    @Override
    public Set<String> getSupportedExtensions() {
        return null;
    }

    @Override
    public void check(Certificate cert, Collection<String> unresolvedCritExts) throws CertPathValidatorException {
        try {
            JcaX509CertificateHolder issuerCert = new JcaX509CertificateHolder(caCert);
            JcaX509CertificateHolder certToCheck = new JcaX509CertificateHolder((X509Certificate) cert);

            if (certToCheck.getIssuer().equals(issuerCert.getSubject())) {
                String message = Utils.getStatusMessage(responderPair.getPrivate(), issuerCert,
                        revokedSerialNumber, certToCheck);
                if (message.endsWith("good")) {
                    System.out.println(message);
                } else {
                    throw new CertPathValidatorException(message);
                }
            }

        } catch (CertificateEncodingException | OperatorCreationException | IOException | OCSPException e) {
            throw new CertPathValidatorException("exception verifying certificate: " + e, e);
        }
    }
}
