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
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
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
import lombok.extern.slf4j.Slf4j;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
/**
 * userController.
 *
 * SpringBoot controller for REST API (backend)
 *  
 */
@CrossOrigin (origins = "*", exposedHeaders = "*", allowedHeaders = "*")
@Slf4j
@Controller
public class uiController {
	private static ResourceBundle bundle = ResourceBundle.getBundle("messages"); //default locale;

    @Autowired private Environment env;
/**
 * uiController
 * @throws IOException 
 * @throws JAXBException 
 * @throws InvalidPathException 
 * 
 */

    @GetMapping("/page")
    public String getPage(Model model) throws InvalidPathException, JAXBException, IOException { 
    	log.info(new MessageFormat(bundle.getString("ldap.debug")).format(new Object[] {"get", "/page", ""}));
    	
    	// Forward SPIF descriptors to Thymeleaf
    	SpifDir spifi = new SpifDir();
    	model.addAttribute("descriptors", spifi.get());
    	
    	log.debug(new MessageFormat(bundle.getString("ldap.debug")).format(new Object[] {"get", "/page", "ok"}));
    	return "clearances"; 
    } // getPage

    
}
