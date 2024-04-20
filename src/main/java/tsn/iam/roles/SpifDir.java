package tsn.iam.roles;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Logger;
import java.util.logging.Level;
import org.xmlspif.spif.SPIF;
import org.xmlspif.spif.SecurityCategoryTagSet;
import org.xmlspif.spif.SecurityClassification;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;
import lombok.extern.slf4j.Slf4j;

import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.MessageFormat;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
@Slf4j
public class SpifDir {
    private final ResourceBundle bundle = ResourceBundle.getBundle("messages"); //default locale
    private Map<ASN1ObjectIdentifier,SpifDescriptor> spifs = new HashMap<ASN1ObjectIdentifier,SpifDescriptor>();
    private String spifPath;
       
    // Inspect the SPIF Directory
    public SpifDir(String spifPath) throws JAXBException,InvalidPathException, IOException {
   		this.spifPath = spifPath;
   		log.info(new MessageFormat(bundle.getString("spif.path")).format(new Object[] {spifPath}));
   		for (File file : new File(spifPath).listFiles()) { // loop on the SPIF directory	 				
 			try { 
 				Spif spif = new Spif(spifPath, file.getName()); // decode spif
 				SpifDescriptor sd = new SpifDescriptor(spif.getPolicyId(),spif.getPolicyName(),spif.getFileName());
				// new OId
 				spifs.put(spif.getPolicyId(),sd); 
  				log.info(new MessageFormat(bundle.getString("spif.loaded")).format(new Object[] {spif.getPolicyId().toString(), "",spif.getPolicyName(), file.getName()}));
   			}  catch (JAXBException e) { continue; } // skip to next file; logged elsewhere
    	} // for
    } // SpifInfo


  
  
//    public String getLACV(String policyID, String role){
//        for(int i = 0; i<spifMap.get(policyID).size();i++){
//            String str =  spifMap.get(policyID).get(i).values().toString().substring(1, spifMap.get(policyID).get(i).values().toString().length()-1);
//            LOGGER.info("Role label and policy ID received : " + policyID + " - " + role);
//            if(str.equals(role)){
//                LOGGER.info("LACV returned : " + spifMap.get(policyID).get(i).keySet().toString().substring(1, spifMap.get(policyID).get(i).keySet().toString().length()-1)); 
//                return spifMap.get(policyID).get(i).keySet().toString().substring(1, spifMap.get(policyID).get(i).keySet().toString().length()-1);
//            }
//        }
//        return "null";
//    }



//    public String getName(ASN1ObjectIdentifier policyID, Integer lacv){
//    	rlog.doLog(Level.FINE,"spif.getName", new Object[] {policyID,lacv});
//    	BigInteger lacv = spifMap.get(policyID);
//    	if (ht != null) {
//    		String clearance = ht.get(lacv.toString());
//    		if (clearance != null) {    			
//    			rlog.doLog(Level.FINE,"spif.getName.ok", new Object[] {clearance});
//    			return clearance;
//    		}
//   	}
//    	rlog.doLog(Level.FINE,"spif.getName.nok", new Object[] {});
//    	return null; // policy or Lacv not found
//    } // getName

    
    public SpifDescriptor get(ASN1ObjectIdentifier oid) throws FileNotFoundException { 
    	SpifDescriptor sd = spifs.get(oid);
    	if (sd == null) {
    		log.debug(new MessageFormat(bundle.getString("spif.getName.nok")).format(new Object[] {oid}));
        	throw new FileNotFoundException(new MessageFormat(bundle.getString("spif.getName.nok")).format(new Object[] {oid}));
    	}
    	return sd;
    }
    public Map<ASN1ObjectIdentifier,SpifDescriptor> get() { return spifs; }
    
    public String toString() { 
    	String result="";
    	for (Map.Entry<ASN1ObjectIdentifier,SpifDescriptor>entry: spifs.entrySet())
    		result += entry.getKey().toString() + " , " + entry.getValue().name() + " - ";
    	return result;
    } // toString
    
    public ArrayList<SpifDescriptor> getSpifDescriptors() {
    	ArrayList<SpifDescriptor> sd = new ArrayList<SpifDescriptor>();
    	for (SpifDescriptor entry: spifs.values()) sd.add(entry);
    	return sd;	
    }
    
}
