package tsn.iam.roles;

import java.math.BigInteger;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.ResourceBundle;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class Policy {
	private String name;
	private ASN1ObjectIdentifier oid;
	private HashMap<String,BigInteger> securityClassifications = new HashMap();
 
 	public Policy(String name, ASN1ObjectIdentifier oid) {
 		this.name = name;
 		this.oid = oid;
 	} // Policy
 	
 	public void addClassif(String name,BigInteger lacv) { securityClassifications.put(name, lacv); }
 	public Integer securityClassificationsSize() { return securityClassifications.size(); }
 	
 	public String toString() {
 		final ResourceBundle bundle = ResourceBundle.getBundle("messages"); //default locale;
 		return new MessageFormat(bundle.getString("spif.policy")).format(new Object[] {
 				oid.toString(),securityClassifications.size(), name
 			});

 	}
} // Policy class
