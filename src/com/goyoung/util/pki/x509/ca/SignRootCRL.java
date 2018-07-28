package com.goyoung.util.pki.x509.ca;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Calendar;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

public class SignRootCRL {

	@SuppressWarnings("deprecation")
	public static void main(String[] args) throws CertificateException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchProviderException, SecurityException, SignatureException, CRLException {
		
		Security.addProvider(new BouncyCastleProvider());

		File privKeyFile = new File("./test-root-ca-priv.der");
		BufferedInputStream bis = new BufferedInputStream(new FileInputStream(privKeyFile));

		byte[] privKeyBytes = new byte[(int) privKeyFile.length()];
		bis.read(privKeyBytes);
		bis.close();
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		KeySpec ks = new PKCS8EncodedKeySpec(privKeyBytes);
		RSAPrivateKey caCrlPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(ks);
		
		// load the Root CA Cert for using for AKI
		FileInputStream fis = new FileInputStream("./test-root-ca.cer");
		BufferedInputStream bis1 = new BufferedInputStream(fis);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate RootCACert = (X509Certificate) cf.generateCertificate(bis1);

		X509V2CRLGenerator   crlGen = new X509V2CRLGenerator();

		Calendar cal = Calendar.getInstance();
		Date now =  cal.getTime();
		Date nextUpdate =  cal.getTime();

		nextUpdate.setYear(nextUpdate.getDate() + 183);

		crlGen.setIssuerDN(new X500Principal(RootCACert.getSubjectDN().toString()));
		 
		crlGen.setThisUpdate(now);
		crlGen.setNextUpdate(nextUpdate);
		crlGen.setSignatureAlgorithm("SHA256WithRSA");
		 
		 
		//crlGen.addCRLEntry(BigInteger.ONE, now, CRLReason.privilegeWithdrawn);
		 
		 
		crlGen.addExtension(X509Extensions.AuthorityKeyIdentifier,
		                  false, new AuthorityKeyIdentifierStructure(RootCACert));
		crlGen.addExtension(X509Extensions.CRLNumber,
		                  false, new CRLNumber(BigInteger.ONE));
		 
		 
		X509CRL    crl = crlGen.generateX509CRL(caCrlPrivateKey, "BC");
		
		System.out.write(crl.getEncoded());
		
		FileOutputStream fos = new FileOutputStream("./test-root-crl.crl");
		
		fos.write(crl.getEncoded());
		fos.close();

		
	}

}
