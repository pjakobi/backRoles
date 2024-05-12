package tsn.iam.roles;

import java.io.File;
import java.math.BigInteger;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.List;
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
    private final RolesLogger rlog=new RolesLogger(Spif.class.getName());
    private static SPIF spif;
	
	Spif(String spifPath, String fileName) throws JAXBException {	
		try {
			// decode XML
			Unmarshaller unmarshaller ;
	    	JAXBContext context = JAXBContext.newInstance(SPIF.class);
	    	unmarshaller = context.createUnmarshaller();
    		spif = (SPIF) unmarshaller.unmarshal(new File(spifPath+ "/" + fileName));
    		rlog.doLog(Level.FINE, "spif.start", new Object[] {fileName, spif.getSecurityPolicyId().getId(), spif.getSecurityPolicyId().getName()});
    	} catch (JAXBException e) { 
    		rlog.doLog(Level.WARNING, "spif.decodeErr", new Object[] {fileName,e.getLocalizedMessage()});
    		throw new JAXBException(rlog.toString("spif.decodeErr", new Object[] {fileName,e.getLocalizedMessage()})); 
    	}
	} // spifFile
	public SPIF get() { return spif; }
} // class
