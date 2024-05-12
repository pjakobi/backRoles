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

import org.xmlspif.spif.ObjectIdData;
import org.xmlspif.spif.SPIF;
import org.xmlspif.spif.SecurityCategoryTagSet;
import org.xmlspif.spif.SecurityClassification;

import jakarta.annotation.PostConstruct;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.DependsOn;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
@Slf4j
@Component
public class SpifDir {
    @Autowired private Environment env;
    @Value("${spif.path}") String spifPath;
    private final ResourceBundle bundle = ResourceBundle.getBundle("messages"); //default locale
    private static Map<ASN1ObjectIdentifier,SPIF> spifs  = new HashMap();

    String getName(ASN1ObjectIdentifier oid) {
    	for (SPIF spif: spifs.values())
    		if (oid.toString().equals(spif.getSecurityPolicyId().getId()))
    			return spif.getSecurityPolicyId().getName();
    	
    	log.warn(new MessageFormat(bundle.getString("spif.jaxbErr")).format(new Object[] {oid.toString()})); // should not happen
    	return "";
    }
    
    @PostConstruct
    private void postConstruct() {
   		this.spifPath = env.getProperty("spif.path");
   		log.info(new MessageFormat(bundle.getString("spif.path")).format(new Object[] {spifPath}));
   		for (File file : new File(spifPath).listFiles()) { // loop on the SPIF directory	 				
 			try { 
 				SPIF spif = (new Spif(spifPath, file.getName())).get(); // decode spif
 				String oidStr = spif.getSecurityPolicyId().getId();
 				ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(oidStr);
 				if (spifs.containsKey(oid))
 					log.warn(new MessageFormat(bundle.getString("spif.duplicate")).format(new Object[] {oid.toString(), file.getName()}));
 				else {
  					log.info(new MessageFormat(bundle.getString("spif.loaded")).format(new Object[] {oid.toString(), file.getName()}));
  					spifs.put(oid, spif);
 				}
   			}  catch (JAXBException e) { continue; } // skip to next file; logged elsewhere
    	} // for
    } // SpifInfo

    public static Map<ASN1ObjectIdentifier,SPIF> get() { return spifs; }
    

  
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

    


    
}
