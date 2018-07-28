package com.goyoung.util.pki.x509.ca;

import com.gyoung.util.crypto.blockchain.RootChain;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;

import org.apache.commons.codec.binary.Base64;

public class SignRootPABC {

    public static void main(String[] args) throws CertificateEncodingException,
            InvalidKeyException, IllegalStateException,
            NoSuchProviderException, NoSuchAlgorithmException,
            SignatureException, IOException {

        Security.addProvider(new BouncyCastleProvider());

        // Generate a 4096-bit RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(4096);
        KeyPair keypair = keyGen.genKeyPair();
        //PublicKey publicKey = keypair.getPublic();
        Calendar cal = Calendar.getInstance();

        // cal.add(cal.getTime());
        Date startDate = cal.getTime();
        Date expiryDate = cal.getTime();

        expiryDate.setYear(expiryDate.getYear() + 30);
        BigInteger serialNumber = new BigInteger(256, new Random());

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        X500Principal dnName = new X500Principal("CN=ACME ROOT Certification Authority, OU=Very Good Security Certification Authority, O=ACME Inc, C=US");

        certGen.setSerialNumber(serialNumber);
        certGen.setIssuerDN(dnName);
        certGen.setNotBefore(startDate);
        certGen.setNotAfter(expiryDate);
        certGen.setSubjectDN(dnName); // note: same as issuer
        certGen.setPublicKey(keypair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSA");
        certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true, 0));

        X509Certificate cert = certGen.generate(keypair.getPrivate(), "BC");
        // System.out.println(cert);

        //Let's only add the public key and not metadata to the blockchain:
        //TODO: let's hash the Binary Public Key from TBS Certificate and not the base64 encoding DOH!!
        String sRootCert[] = {Base64.encodeBase64String(cert.getPublicKey().getEncoded())};
        RootChain.go(sRootCert);

        //do something with the output..
        //in the real world a root CA would be generated on a harware crypto device for secure RNG and storage
        FileOutputStream fos = new FileOutputStream("./test-root-ca.cer");
        fos.write(cert.getEncoded());
        fos.close();

        FileOutputStream fos1 = new FileOutputStream("./test-root-ca-priv.der");
        fos1.write(keypair.getPrivate().getEncoded());
        fos1.close();

        FileOutputStream fos2 = new FileOutputStream("./test-root-ca-pub.der");
        fos2.write(keypair.getPublic().getEncoded());
        fos2.close();
    }

}
