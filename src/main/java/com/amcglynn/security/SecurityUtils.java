package com.amcglynn.security;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class SecurityUtils {

    public static X509Certificate readCertificate(byte[] certContents) throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        InputStream certStream = new ByteArrayInputStream(certContents);
        return (X509Certificate) certificateFactory.generateCertificate(certStream);
    }

    public static PrivateKey readPrivateKey(String keyContents) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        String privateKeyText = keyContents.replaceAll("\\n", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "");

        KeyFactory kf = KeyFactory.getInstance("RSA");
        byte[] decoded = Base64.getDecoder().decode(privateKeyText);
        PKCS8EncodedKeySpec keySpecPv = new PKCS8EncodedKeySpec(decoded);

        return kf.generatePrivate(keySpecPv);
    }

    public static KeyStore getEmptyKeyStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        return keyStore;
    }

    public static byte[] signData(PrivateKey privateKey, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public static boolean verifySignature(byte[] data,
                                          byte[] digitalSignature,
                                          PublicKey publicKey,
                                          Signature signature) throws SignatureException, InvalidKeyException {
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(digitalSignature);
    }

}
