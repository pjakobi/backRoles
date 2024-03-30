package tsn.iam.roles;

import java.io.IOException;
import java.util.Date;
import java.util.ResourceBundle;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.ldap.LdapName;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.X509Extension;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AttributeCertificateInfo;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;

public class AttributeCertRequest {
	private static final String className = AttributeCertRequest.class.getName();
    private static final Logger LOGGER = Logger.getLogger( className );
    private final ResourceBundle bundle = ResourceBundle.getBundle("messages"); //default locale
    private final RolesLogger rlog=new RolesLogger(className);
    
    @Autowired Environment env;
	public AttributeCertRequest (
			LdapName counterDn,
			SerialNumber serialNumber,
			LdapName holder, 
			LdapName requestor, 
			int clearance, 
			ASN1ObjectIdentifier policyID, 
			Date iStart, 
			Date iEnd, 
			String description) throws IOException, NamingException, OperatorCreationException, NoSuchAlgorithmException, NoSuchProviderException {
		String acDname = env.getProperty("ac.base");
        rlog.doLog(Level.FINE, "ac.add",new Object[] {serialNumber.toString()});
        String strDName = "serialNumber=" + serialNumber.toString() + "," + acDname;
        X500Name subject = new X500Name(bundle.getString("ac.label"));

        
        // We provide a key pair in the CSR as PKCS10 mandates it, but it will be ignored later on
        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("DSA", "BC");
        kpg.initialize(2048);
        java.security.KeyPair kp = kpg.genKeyPair();

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(subject, kp.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = csBuilder.build(kp.getPrivate());
        
        //org.bouncycastle.asn1.x500.X500Name issuer, 
        //java.math.BigInteger serial, 
        //java.util.Date notBefore, 
        //java.util.Date notAfter, 
        //org.bouncycastle.asn1.x500.X500Name subject, 
        //java.security.PublicKey publicKey
        
        //new JcaX509v3CertificateBuilder(caCert, new SerialNumber(counterDn), iStart, iEnd, dn, kp.getPublic());
        
        Vector oids = new Vector();
        Vector values = new Vector();
        
        //X509Extension ext = new X509Extension();
        
        //DERBitString derClassList = new DERBitString(clearance.getBytes());
        //oids.add(X509Extension.SubjectAlternativeName(holder));
        
        
        DERGeneralizedTime start = new DERGeneralizedTime(iStart.toString());
        DERGeneralizedTime end = new DERGeneralizedTime(iEnd.toString());
        ASN1EncodableVector envec = new ASN1EncodableVector();
        //envec.add(policyID);
        //envec.add(derClassList);
        DERSequence derSequence = new DERSequence(envec);

        Attributes attributes = new BasicAttributes();
        Attribute clearanceRequest = new BasicAttribute("objectClass", "clearanceRequest");
        Attribute top = new BasicAttribute("objectClass", "top");
        Attribute clearanceAttribute;
		try { clearanceAttribute = new BasicAttribute("clearance", derSequence.getEncoded()); } 
		catch (IOException e) {
			rlog.doLog(Level.WARNING, "ac.add.error",new Object[] {e.getLocalizedMessage()});
			e.printStackTrace();
			throw new IOException(e.getLocalizedMessage());
		}
        Attribute startAttribute = new BasicAttribute("notBeforeTime", start.getTimeString());
        Attribute endAttribute = new BasicAttribute("notAfterTime", end.getTimeString());
        Attribute reqAttribute = new BasicAttribute("requestor", requestor.toString());
        Attribute holdAttribute = new BasicAttribute("holder", holder);
        Attribute descrAttribute = new BasicAttribute("description",description);
        
        attributes.put(clearanceRequest);    
        attributes.put(clearanceAttribute);
        attributes.put(descrAttribute);
        attributes.put(startAttribute);
        attributes.put(endAttribute);
        attributes.put(reqAttribute);
        attributes.put(holdAttribute);
        
        
        
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        
        JndidapAPI.addACRequest(new LdapName(strDName), attributes);
	}
}
