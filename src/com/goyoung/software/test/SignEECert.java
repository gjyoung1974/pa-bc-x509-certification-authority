package com.goyoung.software.test;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

public class SignEECert {

    @SuppressWarnings("deprecation")
    public static void main(String[] args) throws CertificateEncodingException, InvalidKeyException,
            IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, IOException,
            InvalidKeySpecException, CertificateParsingException {
        Security.addProvider(new BouncyCastleProvider());

        File privKeyFile = new File("./test-sub-ca-priv.der");
        BufferedInputStream bis = new BufferedInputStream(new FileInputStream(privKeyFile));

        byte[] privKeyBytes = new byte[(int) privKeyFile.length()];
        bis.read(privKeyBytes);
        bis.close();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        KeySpec ks = new PKCS8EncodedKeySpec(privKeyBytes);
        RSAPrivateKey caPrivKey = (RSAPrivateKey) keyFactory.generatePrivate(ks);

        // Generate a 1024-bit RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keypair = keyGen.genKeyPair();
        PublicKey publicKey = keypair.getPublic();
        Calendar cal = Calendar.getInstance();

        // cal.add(cal.getTime());
        Date startDate = cal.getTime();
        Date expiryDate = cal.getTime();

        expiryDate.setMonth(expiryDate.getMonth() + 36);
        BigInteger serialNumber = new BigInteger(256, new Random());
        // set it manually:
        // BigInteger serialNumber = BigInteger.valueOf(Long.valueOf("5")); // serial
        // number
        // for
        // certificate

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        X500Principal sName = new X500Principal("CN=fleet.verygoodsecurity.io, OU=Fleet-Test, O=VGS Inc, C=US");
        X500Principal iName = new X500Principal("CN=VGS DEV Issuing CA, OU=Very Good DEV Certification Authority, O=VGS Inc, C=US");

        certGen.setSerialNumber(serialNumber);
        certGen.setIssuerDN(iName);
        certGen.setNotBefore(startDate);
        certGen.setNotAfter(expiryDate);
        certGen.setSubjectDN(sName); // note: same as issuer
        certGen.setPublicKey(keypair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSA");

        KeyUsage ku = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment );
        X509Extension extension = new X509Extension(false, new DEROctetString(ku));

//        Vector<DERObjectIdentifier> oidvec = new Vector<DERObjectIdentifier>();
//        oidvec.add(X509Extensions.ExtendedKeyUsage);
//        Vector<DERObjectIdentifier> oids = new Vector<DERObjectIdentifier>();
//        Vector<X509Extension> values = new Vector<X509Extension>();
//
//        ExtendedKeyUsage extendedKeyUsage1 = new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth);
//        X509Extension extendedKeyUsage = new X509Extension(false, new DEROctetString(extendedKeyUsage1));
//
//        ExtendedKeyUsage extendedKeyUsage2 = new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth);
//        X509Extension EextendedKeyUsage = new X509Extension(false, new DEROctetString(extendedKeyUsage2));
//
//        // DERSet(attribute),
//        oids.add(X509Extensions.ExtendedKeyUsage);
//        values.add(new X509Extension(false, new DEROctetString(extendedKeyUsage1)));
//        values.add(new X509Extension(false, new DEROctetString(extendedKeyUsage1)));
//
//        oids.add(X509Extensions.ExtendedKeyUsage);
//        values.add(new X509Extension(false, new DEROctetString(EextendedKeyUsage.getValue())));

        X509Extension SKIextension = new X509Extension(false, new DEROctetString(new SubjectKeyIdentifierStructure(publicKey)));


        certGen.addExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        certGen.addExtension(X509Extensions.KeyUsage, false, extension.getValue());
        certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, SKIextension.getValue());

        X509Certificate cert = certGen.generate(caPrivKey, "BC");

        System.out.println(cert);

        FileOutputStream fos = new FileOutputStream("./test-EE.cer");
        fos.write(cert.getEncoded());
        fos.close();

        FileOutputStream fos1 = new FileOutputStream("./test-EE-priv.der");
        fos1.write(keypair.getPrivate().getEncoded());
        fos1.close();

        FileOutputStream fos2 = new FileOutputStream("./test-EE-pub.der");
        fos2.write(keypair.getPublic().getEncoded());
        fos2.close();
    }

}
