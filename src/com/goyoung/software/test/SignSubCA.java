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
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

@SuppressWarnings("deprecation")
public class SignSubCA {

    public static void main(String[] args) throws InvalidKeyException,
            IllegalStateException, NoSuchProviderException,
            NoSuchAlgorithmException, SignatureException, IOException,
            InvalidKeySpecException, CertificateException {
        Security.addProvider(new BouncyCastleProvider());

        File privKeyFile = new File("./test-root-ca-priv.der");
        BufferedInputStream bis = new BufferedInputStream(new FileInputStream(privKeyFile));

        byte[] privKeyBytes = new byte[(int) privKeyFile.length()];
        bis.read(privKeyBytes);
        bis.close();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        KeySpec ks = new PKCS8EncodedKeySpec(privKeyBytes);
        RSAPrivateKey caPrivKey = (RSAPrivateKey) keyFactory.generatePrivate(ks);

        // get the Root CA Cert
        FileInputStream fis = new FileInputStream("./test-root-ca.cer");
        BufferedInputStream bis1 = new BufferedInputStream(fis);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate RootCACert = (X509Certificate) cf.generateCertificate(bis1);

        // Generate a 2048-bit RSA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keypair = keyGen.genKeyPair();
        PublicKey publicKey = keypair.getPublic();
        Calendar cal = Calendar.getInstance();

        // cal.add(cal.getTime());
        Date startDate = cal.getTime();
        Date expiryDate = cal.getTime();

        expiryDate.setYear(expiryDate.getYear() + 10);
        BigInteger serialNumber = new BigInteger(256, new Random());
        // or set it specifically
        // BigInteger serialNumber = BigInteger.valueOf(Long.valueOf("2")); // serial
        // number
        // for
        // certificate

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        X500Principal sName = new X500Principal("CN=VGS DEV Issuing CA, OU=Very Good DEV Certification Authority, O=VGS Inc, C=US");
        X500Principal iName = RootCACert.getSubjectX500Principal();

        certGen.setSerialNumber(serialNumber);
        certGen.setIssuerDN(iName);
        certGen.setNotBefore(startDate);
        certGen.setNotAfter(expiryDate);
        certGen.setSubjectDN(sName); // note: same as issuer
        certGen.setPublicKey(keypair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSA");

        // add KeyUsage flags
        KeyUsage ku = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign);
        X509Extension extension = new X509Extension(false, new DEROctetString(ku));

        // add EKU OID

        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage);
        X509Extension EKUextension = new X509Extension(false, new DEROctetString(extendedKeyUsage));


        // add BC, SKI, AKI values
        X509Extension BCextension = new X509Extension(true, new DEROctetString(new BasicConstraints(0)));
        X509Extension SKIextension = new X509Extension(false, new DEROctetString(new SubjectKeyIdentifierStructure(publicKey)));
        AuthorityKeyIdentifierStructure AKI = new AuthorityKeyIdentifierStructure(RootCACert);

        // AIA CACert list
        //GeneralName CACertLocation = new GeneralName(6, new DERIA5String("http://crl.gordonyoung.com/root.crt"));
        //certGen.addExtension(X509Extensions.AuthorityInfoAccess.getId(), false,new AuthorityInformationAccess(X509ObjectIdentifiers.id_ad_caIssuers, CACertLocation));

        // AIA OCSP list
        // GeneralName OCSPLocation = new GeneralName(6, new
        // DERIA5String("http://crl.gordonyoung.com/ocsp/"));
        // certGen.addExtension(X509Extensions.AuthorityInfoAccess.getId(),
        // false,
        // new AuthorityInformationAccess(
        // X509ObjectIdentifiers.ocspAccessMethod,
        // OCSPLocation)
        // );

//        // Add the CRL distribution point here:
//        ArrayList<DistributionPoint> distpoints = new ArrayList<DistributionPoint>();
//        GeneralName gn = new GeneralName(6, new DERIA5String("http://crl.test.com/root.crl"));
//        GeneralNames gns = new GeneralNames(gn);
//        DistributionPointName dpn = new DistributionPointName(0, gns);
//        distpoints.add(new DistributionPoint(dpn, null, null));
//        CRLDistPoint ext = new CRLDistPoint(distpoints.toArray(new DistributionPoint[0]));

//        // add a CP extention
//        String cps = "http://crl.gordon.com/cps.hmtl";
//        PolicyQualifierInfo policyQualifierInfo = new PolicyQualifierInfo(cps);
//        DERObjectIdentifier policyObjectIdentifier = new DERObjectIdentifier("2.16.840.1.114171.500.0.0");
//        PolicyInformation policyInformation = new PolicyInformation(policyObjectIdentifier, new DERSequence(policyQualifierInfo));

//		certGen.addExtension(X509Extensions.CertificatePolicies, false,new DERSequence(policyInformation));

//		certGen.addExtension(X509Extensions.CRLDistributionPoints.getId(),false, ext);

        certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, SKIextension.getValue());
//		certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, AKI);

//        certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        certGen.addExtension(X509Extensions.KeyUsage, true, extension.getValue());
        certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true, 0));

        X509Certificate cert = certGen.generate(caPrivKey, "BC");
        System.out.println(cert);

        FileOutputStream fos = new FileOutputStream("./test-sub-ca.cer");
        fos.write(cert.getEncoded());
        fos.close();

        FileOutputStream fos1 = new FileOutputStream("./test-sub-ca-priv.der");
        fos1.write(keypair.getPrivate().getEncoded());
        fos1.close();

        FileOutputStream fos2 = new FileOutputStream("./test-sub-ca-pub.der");
        fos2.write(keypair.getPublic().getEncoded());
        fos2.close();

    }
}
