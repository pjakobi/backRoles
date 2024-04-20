package tsn.iam.roles;

import java.io.File;
import java.math.BigInteger;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.xmlspif.spif.SPIF;
import org.xmlspif.spif.SecurityClassification;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;
import lombok.extern.slf4j.Slf4j;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

@Slf4j
public class Spif {
    private final ResourceBundle bundle = ResourceBundle.getBundle("messages"); //default locale

    
	private static Map<BigInteger, String> classifications = new HashMap<BigInteger,String>(); // LACV, label
	private static ASN1ObjectIdentifier policyId;
	private static String policyName;
	private static String fileName;

	Spif(String spifPath, String fileName) throws JAXBException {	
		try {
			// decode XML
	    	Unmarshaller unmarshaller ;
	    	JAXBContext context = JAXBContext.newInstance(SPIF.class);
	    	unmarshaller = context.createUnmarshaller();
    		SPIF spif = (SPIF) unmarshaller.unmarshal(new File(spifPath+ "/" + fileName));
    		log.info(new MessageFormat(bundle.getString("spif.start")).format(new Object[] {fileName, spif.getSecurityPolicyId().getId()}));
    		
    		// Extract data
    		this.policyId = new ASN1ObjectIdentifier(spif.getSecurityPolicyId().getId());
    		this.policyName = spif.getSecurityPolicyId().getName();
    		this.fileName = fileName;
    		log.debug(new MessageFormat(bundle.getString("spif.description")).format(new Object[] {policyId.toString(), policyName}));
    		
    		spif.getSecurityClassifications().getSecurityClassification().forEach(classif -> {
    			classifications.put(classif.getLacv(), classif.getName());
    			log.trace(new MessageFormat(bundle.getString("spif.classif")).format(new Object[] {policyId.toString(), classif.getLacv(),classif.getName()}));
    		});
			log.trace(new MessageFormat(bundle.getString("spif.decoded")).format(new Object[] {fileName}));
    	} catch (JAXBException e) { 
    		log.warn(new MessageFormat(bundle.getString("spif.decodeErr")).format(new Object[] {fileName,e.getLocalizedMessage()}));
    		throw new JAXBException(e.getLocalizedMessage()); 
    	}
	} // spifFile
	
	public ASN1ObjectIdentifier getPolicyId() { return this.policyId; }
	public String getPolicyName() { return this.policyName; }
	public String getFileName() { // base name only
		File myFile = new File(fileName);
		return myFile.getName(); 
	}
	
	public Map<BigInteger,String> getClassifications() { return this.classifications; }

	public String toString() { return ("oid: " + policyId.toString() + " (" + policyName + ") - "); }
	
} // class
