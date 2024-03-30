package tsn.iam.roles;

import java.io.File;
import java.io.FileNotFoundException;

//import tsn.iam.roles.AttributeCertificate.*;
//import tsn.iam.roles.AttributeCertificate.SPIF.SpifInfo;
//import tsn.iam.roles.LDAP.*;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.net.InetAddress;
import java.nio.file.InvalidPathException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger; // SEVERE, WARNING, INFO, CONFIG, FINE, FINER, FINEST
import java.net.InetAddress;

import javax.naming.InvalidNameException;
import javax.naming.NameAlreadyBoundException;
import javax.naming.NamingException;
import javax.naming.ldap.LdapName;

import org.bouncycastle.asn1.x509.AttributeCertificateInfo;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.expression.ParseException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.unix4j.Unix4j;
import org.unix4j.line.Line;

import jakarta.xml.bind.JAXBException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
/**
 * rolesController.
 *
 * SpringBoot controller for REST API (backend)
 *  
 */
@CrossOrigin (origins = "*", exposedHeaders = "*", allowedHeaders = "*")

@RestController
public class testController {
	@Autowired private Environment env;
    private LdapName acDname=null;
    private SpifDir spifi;
    private static RolesLogger rlog=new RolesLogger(testController.class.getName());
    
/**
 * rolesController
 * @param ldapConfigFile : typically /etc/openldap/ldap.conf. Contains the various ldap parameters.
 * @param pwFname : contains the bind password only.
 * @throws URISyntaxException 
 * @throws FileNotFoundException 
 * @throws InvalidNameException 
 * 
 * @throws NamingException : incorrect bind DN
 * @throws InvalidPathException : invalid SPIF directory
 * @throws JAXBException : invalid SPIF
 * @throws IOException : read error on ldapConfigFile
 * 
 * All other parameters from application.properties go through the Context bean.
 * @throws InterruptedException : sleep interrupted
 * 
 */


/**
 * test()
 * 
 * Application "ping".
 * @throws JAXBException 
 * @throws InvalidPathException 
 * 
 */
    @GetMapping("/test2")
    public ResponseEntity<String> test() throws NumberFormatException, IOException, InvalidNameException, NamingException, InterruptedException, OperatorCreationException, NoSuchAlgorithmException, NoSuchProviderException, InvalidPathException, JAXBException {
    	rlog.doLog(Level.INFO,"spif.test",new Object[] {});
    	Props properties=new Props(env);

    	
    	SerialNumber sn = new SerialNumber(acDname);
    	AttributeCertRequest ac = new AttributeCertRequest (acDname,new SerialNumber(acDname),
    			new LdapName("CN=John Smith, O=Isode Limited"), 
    			new LdapName("CN=John Steed, O=Isode Limited"), 
    			1, 
    			new ASN1ObjectIdentifier("2.16.840.1.101.2.1.12.0.4"),
    			new Date("December 17, 1995 03:24:00"),
    			new Date("December 17, 1996 03:24:00"),
    			"description");


      
       
    	rlog.doLog(Level.FINE,"spif.test.ok",new Object[] {});
    	
    	return new ResponseEntity<String>(HttpStatus.OK);
    } // test
}
