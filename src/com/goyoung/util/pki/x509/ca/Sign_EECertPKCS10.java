package com.goyoung.util.pki.x509.ca;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
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

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

@SuppressWarnings("deprecation")
public class Sign_EECertPKCS10 {

	public static void main(String[] args) throws InvalidKeyException, IllegalStateException,
			NoSuchProviderException, NoSuchAlgorithmException,
			SignatureException, IOException, InvalidKeySpecException, CertificateException {
		Security.addProvider(new BouncyCastleProvider());
		
		File csrFile = new File("test-EE-pkcs10.der");
		BufferedInputStream bis1 = new BufferedInputStream(new FileInputStream(csrFile)); 

		byte[] csryBytes = new byte[(int)csrFile.length()]; 
		bis1.read(csryBytes); 
		bis1.close(); 

	    PKCS10CertificationRequest csr = new PKCS10CertificationRequest(csryBytes);

		File privKeyFile = new File("./test-root-ca-priv.der");
		BufferedInputStream bis = new BufferedInputStream(new FileInputStream(privKeyFile)); 

		byte[] privKeyBytes = new byte[(int)privKeyFile.length()]; 
		bis.read(privKeyBytes); 
		bis.close(); 
		KeyFactory keyFactory = KeyFactory.getInstance("RSA"); 
		KeySpec ks = new PKCS8EncodedKeySpec(privKeyBytes); 
		RSAPrivateKey caPrivKey = (RSAPrivateKey) keyFactory.generatePrivate(ks); 
		
		// load the Root CA Cert for using for AKI
		FileInputStream fis = new FileInputStream("./test-root-ca.cer");
		BufferedInputStream bis2 = new BufferedInputStream(fis);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate RootCACert = (X509Certificate) cf.generateCertificate(bis2);
		AuthorityKeyIdentifierStructure AKI = new AuthorityKeyIdentifierStructure(RootCACert);
		
		
		Calendar cal = Calendar.getInstance();

		// cal.add(cal.getTime());
		Date startDate = cal.getTime();
		Date expiryDate = cal.getTime();

		expiryDate.setYear((expiryDate.getYear() + 15));
		
		BigInteger serialNumber = new BigInteger(256, new Random());
		

		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		X500Principal sName = new X500Principal(csr.getCertificationRequestInfo().getSubject().toString());
		X500Principal iName  = new X500Principal("CN=ACME ROOT CA, OU=ACME Certification Authority, O=ACME Inc, C=US");
		
		certGen.setSerialNumber(serialNumber);
		certGen.setIssuerDN(iName);
		certGen.setNotBefore(startDate);
		certGen.setNotAfter(expiryDate);
		certGen.setSubjectDN(sName); // note: same as issuer
		certGen.setPublicKey(csr.getPublicKey());
		certGen.setSignatureAlgorithm("SHA256WithRSA");
	
		KeyUsage ku = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign );
		X509Extension extension = new X509Extension(false, new DEROctetString(ku));
		

		        // add BC, SKI, AKI values
				X509Extension BCextension = new X509Extension(true, new DEROctetString(new BasicConstraints(0)));
				X509Extension SKIextension = new X509Extension(false,new DEROctetString(new SubjectKeyIdentifierStructure(csr.getPublicKey())));
				
				// Add the CRL distribution point here:
				ArrayList<DistributionPoint> distpoints = new ArrayList<DistributionPoint>();
				GeneralName gn = new GeneralName(6, new DERIA5String("http://crl.example.com/root.crl"));
				GeneralNames gns = new GeneralNames(gn);
				DistributionPointName dpn = new DistributionPointName(0, gns);
				distpoints.add(new DistributionPoint(dpn, null, null));
				CRLDistPoint ext = new CRLDistPoint(distpoints.toArray(new DistributionPoint[0]));
				
				 ASN1EncodableVector list = new ASN1EncodableVector();

			        // AIA extension for CA Issuers
			        list.add(new AccessDescription(AccessDescription.id_ad_caIssuers,
			                                       new GeneralName(GeneralName.uniformResourceIdentifier,
			                                                       new DERIA5String("http://aia.example.com/root.crt"))));
			        // AIA extension for OCSP access method.
			        list.add(new AccessDescription(AccessDescription.id_ad_ocsp,
			                                       new GeneralName(GeneralName.uniformResourceIdentifier,
			                                                       new DERIA5String("http://ocsp.example.com/ocsp/"))));

			        certGen.addExtension(X509Extensions.AuthorityInfoAccess.getId(),
                         false,
                         AuthorityInformationAccess.getInstance(new DERSequence(list)));
			        

				// add a CP extention
				String cps = "http://pki.example.com/cps.hmtl";
				PolicyQualifierInfo policyQualifierInfo = new PolicyQualifierInfo(cps);
				DERObjectIdentifier policyObjectIdentifier = new DERObjectIdentifier("2.16.840.1.114171.500.0.0");
				PolicyInformation policyInformation = new PolicyInformation(policyObjectIdentifier, new DERSequence(policyQualifierInfo));

				certGen.addExtension(X509Extensions.CRLDistributionPoints.getId(),false, ext);
				certGen.addExtension(X509Extensions.KeyUsage, true,extension.getValue());
				certGen.addExtension(X509Extensions.BasicConstraints, true,BCextension.getValue());
				certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false,SKIextension.getValue());
				certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, AKI);
				
				certGen.addExtension(X509Extensions.CertificatePolicies, false,new DERSequence(policyInformation));

				
		X509Certificate cert = certGen.generate(caPrivKey, "BC");
		
		System.out.println(cert);

		FileOutputStream fos = new FileOutputStream("./test-EE-pkcs10.cer");
		fos.write(cert.getEncoded());
		fos.close();

		FileOutputStream fos2 = new FileOutputStream("./test-EE-pub-pkcs10.der");
		fos2.write(csr.getPublicKey().getEncoded());
		fos2.close();
	}

}
