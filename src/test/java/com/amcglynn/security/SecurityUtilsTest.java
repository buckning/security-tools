package com.amcglynn.security;

import org.junit.BeforeClass;
import org.junit.Test;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static com.amcglynn.security.TestData.CERTIFICATE_CONTENTS;
import static com.amcglynn.security.TestData.PRIVATE_KEY_CONTENTS;
import static com.amcglynn.security.TestData.SIGNATURE_CONTENTS;
import static org.assertj.core.api.Assertions.assertThat;

public class SecurityUtilsTest {

    private static final String ALGORITHM = "SHA256WithRSA";

    private static byte[] certFileContents;
    private static byte[] keyFileContents;
    private static byte[] dataFileContents;
    private static byte[] signatureFileContents;

    @BeforeClass
    public static void setUp() throws Exception {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());   // needed to load the private key from file

        certFileContents = CERTIFICATE_CONTENTS.getBytes();
        keyFileContents = PRIVATE_KEY_CONTENTS.getBytes();
        dataFileContents = "testing123\n".getBytes();
        signatureFileContents = Base64.getDecoder().decode(SIGNATURE_CONTENTS.getBytes());
    }

    @Test
    public void testReadCertificate() throws Exception {
        X509Certificate certificate = SecurityUtils.readCertificate(certFileContents);
        assertThat(certificate.getSubjectDN().getName())
                .isEqualTo("EMAILADDRESS=email@address.here, CN=mycert, OU=Engineering, O=None, L=Galway, ST=Connacht, C=IE");
    }

    @Test
    public void testReadPrivateKey() throws Exception {
        PrivateKey privateKey = SecurityUtils.readPrivateKey(new String(keyFileContents));
        assertThat(privateKey.getAlgorithm()).isEqualTo("RSA");
    }

    @Test
    public void testVerifySignatureWithValidSignedFile() throws Exception {
        assertThat(SecurityUtils.verifySignature(dataFileContents, signatureFileContents,
                SecurityUtils.readCertificate(certFileContents).getPublicKey(), Signature.getInstance(ALGORITHM)))
            .isTrue();
    }

    @Test
    public void testVerifySignatureWithInvalidSignedFile() throws Exception {
        assertThat(SecurityUtils.verifySignature("randomData".getBytes(), signatureFileContents,
                SecurityUtils.readCertificate(certFileContents).getPublicKey(), Signature.getInstance(ALGORITHM)))
                .isFalse();
    }

    @Test
    public void testSignDataAndVerify() throws Exception {
        CertAndKeyGen certAndKeyGen = getCertAndKeyGen();
        PrivateKey privateKey = certAndKeyGen.getPrivateKey();
        Certificate certificate = generateSelfSignedCertificate(certAndKeyGen);

        byte[] data = "testSignData".getBytes();

        byte[] digitalSignature = SecurityUtils.signData(privateKey, data);

        assertThat(SecurityUtils.verifySignature(data, digitalSignature,
                certificate.getPublicKey(), Signature.getInstance(ALGORITHM)))
                .isTrue();
    }

    public Certificate generateSelfSignedCertificate(CertAndKeyGen certAndKeyGen) throws Exception {
        return certAndKeyGen.getSelfCertificate(new X500Name(
                "CN=testcn,O=testorg,L=testlocation,C=IE"), (long) 3650 * 24 * 60 * 60);
    }

    private CertAndKeyGen getCertAndKeyGen() throws Exception {
        CertAndKeyGen certAndKeyGen = new CertAndKeyGen("RSA", ALGORITHM, null);
        certAndKeyGen.generate(2048);
        return certAndKeyGen;
    }
}
