package com.goyoung.util.pki.x509.ca;

import com.gyoung.util.crypto.blockchain.RootCASigningChain;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
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
        X500Principal sName = new X500Principal("CN=ACME DEV Issuing CA, OU=ACME DEV Certification Authority, O=ACME Inc, C=US");
        X500Principal iName = RootCACert.getSubjectX500Principal();

        certGen.setSerialNumber(serialNumber);
        certGen.setIssuerDN(iName);
        certGen.setNotBefore(startDate);
        certGen.setNotAfter(expiryDate);
        certGen.setSubjectDN(sName); // note: same as issuer
        certGen.setPublicKey(keypair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSA");


        // add BC, SKI, AKI values
        X509Extension BCextension = new X509Extension(true, new DEROctetString(new BasicConstraints(0)));
        X509Extension SKIextension = new X509Extension(false, new DEROctetString(new SubjectKeyIdentifierStructure(publicKey)));
        AuthorityKeyIdentifierStructure AKI = new AuthorityKeyIdentifierStructure(RootCACert);

        // AIA CACert list
        GeneralName CACertLocation = new GeneralName(6, new DERIA5String("http://aia.example.com/root.crt"));
        certGen.addExtension(X509Extensions.AuthorityInfoAccess.getId(), false, new AuthorityInformationAccess(X509ObjectIdentifiers.id_ad_caIssuers, CACertLocation));

        //TODO: Add an OCSP AIA URI to the array above ^^
        //GeneralName OCSPLocation = new GeneralName(6, new
        //DERIA5String("http://aia.example.com/ocsp/"));
        //certGen.addExtension(X509Extensions.AuthorityInfoAccess.getId(),
        //false,
        //new AuthorityInformationAccess(
        //X509ObjectIdentifiers.ocspAccessMethod,
        //OCSPLocation));

        // Add the CRL distribution point here:
        ArrayList<DistributionPoint> distpoints = new ArrayList<DistributionPoint>();
        GeneralName gn = new GeneralName(6, new DERIA5String("http://crl.example.com/root.crl"));
        GeneralNames gns = new GeneralNames(gn);
        DistributionPointName dpn = new DistributionPointName(0, gns);
        distpoints.add(new DistributionPoint(dpn, null, null));
        CRLDistPoint ext = new CRLDistPoint(distpoints.toArray(new DistributionPoint[0]));

        // add a 'Certification Policies' CP extention
        String cps = "http://cps.example.com/cps.hmtl";
        PolicyQualifierInfo policyQualifierInfo = new PolicyQualifierInfo(cps);
        DERObjectIdentifier policyObjectIdentifier = new DERObjectIdentifier("1.3.6.1.5.5.7.2.1");
        PolicyInformation policyInformation = new PolicyInformation(policyObjectIdentifier, new DERSequence(policyQualifierInfo));

        //Add some common v3 extentions for a Subordinate-issuing CA
        certGen.addExtension(X509Extensions.CertificatePolicies, false, new DERSequence(policyInformation));
        certGen.addExtension(X509Extensions.CRLDistributionPoints.getId(), false, ext);
        certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, SKIextension.getValue());
        certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, AKI);
        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));
        certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true, 0));

        //sign the cert
        X509Certificate cert = certGen.generate(caPrivKey, "BC");
        //System.out.println(cert);

        //Add it to the BlockChain 'log'
        //Let's only add the public key and not x509 metadata to the blockchain:
        RootCASigningChain.bGo(cert.getPublicKey().getEncoded());

        //do something with the output..
        //in the real world a PKI CA would be generated on a hardware crypto device for secure RNG and storage
        FileOutputStream fos = new FileOutputStream("./test-sub-ca.cer");
        fos.write(cert.getEncoded());
        fos.close();

        FileOutputStream fos1 = new FileOutputStream("./test-sub-ca-priv.der");
        fos1.write(keypair.getPrivate().getEncoded());
        fos1.close();


    }
}
