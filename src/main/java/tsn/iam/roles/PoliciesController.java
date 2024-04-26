package tsn.iam.roles;

import java.io.FileNotFoundException;

//import tsn.iam.roles.AttributeCertificate.*;
//import tsn.iam.roles.AttributeCertificate.SPIF.SpifInfo;
//import tsn.iam.roles.LDAP.*;

import java.io.IOException;
import java.nio.file.InvalidPathException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.ResourceBundle;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import jakarta.xml.bind.JAXBException;
import lombok.extern.slf4j.Slf4j;


/**
 * 
 *
 * SpringBoot controller for REST API (backend)
 *  
 */
/**
 * PoliciesController
 * <p>Web service for security policies (SPIFs).
 * See <a href="http://xmlspif.org">xmlspif.org</a> for details
 * </p>
 * @author <A HREF="mailto:pascal.jakobi@gmail.com">pascal.jakobi@gmail.com</a>
 */
@CrossOrigin (origins = "*", exposedHeaders = "*", allowedHeaders = "*")
@RestController
@Slf4j
public class PoliciesController {
    /**
     * Environment bean (application.properties)
     */
    @Autowired private Environment env;
    /**
     * Security Policy Information Files directory
     */
    @Autowired private SpifDir spifDir;
    private static ResourceBundle bundle = ResourceBundle.getBundle("messages"); //default locale;
    @Autowired private LdapService ldapService;
    

/**
 * <h1>Access point /policies</h1>
 * <p>Retrieve a list of Security Policy Information Files from a Directory (stored in application.properties).</p>
 * <p>Returns a JSON array containing name + object id + file name.</p>
 * 
 * @throws InvalidPathException : invalid SPIF directory
 * @throws JAXBException : invalid SPIF
 * @throws IOException : read error on ldapConfigFile
 * 
 * All other parameters from application.properties go through the environment bean.
 * 
 */

    @GetMapping("/policies")
    public ResponseEntity<ArrayList<SpifDescriptor>> getPolicies() throws InvalidPathException, JAXBException, IOException { // File name, obj. id, policy name
    	log.info(new MessageFormat(bundle.getString("spif.getPolicies")).format(new Object[] {}));
    	ArrayList<SpifDescriptor> sd = spifDir.getSpifDescriptors();
    	log.debug(new MessageFormat(bundle.getString("spif.getPolicies.ok")).format(new Object[] {sd.size()}));
    	return new ResponseEntity<ArrayList<SpifDescriptor>> (sd,HttpStatus.OK);   		
    } // getPolicies
    
    
    @GetMapping("/policies/{oid}")
    public ResponseEntity<SpifDescriptor> getPolicyName(@PathVariable("oid") String oid) throws FileNotFoundException,JAXBException,IOException { 
    	try {
    		
    		log.info(new MessageFormat(bundle.getString("spif.getPolicy")).format(new Object[] {oid}));
    		
    		SpifDescriptor result = spifDir.get(new ASN1ObjectIdentifier(oid));
    		log.trace(new MessageFormat(bundle.getString("spif.getPoliciesDetails")).format(new Object[] {oid,result}));
    		log.debug(new MessageFormat(bundle.getString("spif.getPolicy.ok")).format(new Object[] {}));
    		return new ResponseEntity<SpifDescriptor> (result,HttpStatus.OK);
    	} catch (FileNotFoundException e) { 
    		throw new FileNotFoundException(new MessageFormat(bundle.getString("spif.getName.nok")).format(new Object[] {oid}));
    	}
    }
    /**
     * <h1>Access point /policies/{oid}</h1>
     * <p>Returns the contents of a Security Policy Information File : essentially an array of clearances
     * @param oid The policy's object id
     * @throws InvalidPathException : invalid SPIF directory
     * @throws JAXBException : invalid SPIF
     * @throws IOException : read error on ldapConfigFile
     * 
     * All other parameters from application.properties go through the environment bean.
     * 
     */
    //@GetMapping("/policies/{oid}")
    //public ResponseEntity<String> getAvailableClearance(@PathVariable("oid") String oid) throws JAXBException, InvalidPathException, IOException {
    	//log.info(new MessageFormat(bundle.getString("spif.clearances")).format(new Object[] {oid}));
    	//if (spifi == null) spifi = new SpifDir(env.getProperty("spif.path"));
   		//String spifName =  spifi.get(new ASN1ObjectIdentifier(oid));
   		//log.debug(new MessageFormat(bundle.getString("spif.clearances.ok")).format(new Object[] {oid}));
   		//return new ResponseEntity<Map<BigInteger, String>>(spif.getClassifications(),HttpStatus.OK);
    //} // getAvailableClearance
    

} // class PoliciesController
