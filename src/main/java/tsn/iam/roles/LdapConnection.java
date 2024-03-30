package tsn.iam.roles;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.logging.Level;
import javax.naming.ConfigurationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapName;
import org.apache.commons.configuration2.INIConfiguration;
import org.springframework.beans.factory.annotation.Autowired;


public class LdapConnection {
	
	private static InitialLdapContext ctx=null;
	private static RolesLogger rlog=null;
	
	public LdapConnection(URI uri, LdapName login, String pwd) throws FileNotFoundException, IOException, NamingException {
		rlog=new RolesLogger(LdapConnection.class.getName());
		rlog.doLog(Level.FINE, "ldap.conf", new Object[] {uri.toString()});

		
		
		Hashtable<String, String> env = new Hashtable<String, String>();
		env.put(Context.INITIAL_CONTEXT_FACTORY,Constants.ldapCtxFactory);
		env.put(Context.PROVIDER_URL, uri.toString());
		env.put(Context.SECURITY_AUTHENTICATION,"simple");
		env.put(Context.SECURITY_PRINCIPAL,login.toString());
		env.put(Context.SECURITY_CREDENTIALS,pwd);
		env.put("java.naming.ldap.attributes.binary","attributeCertificateAttribute clearance");//TRES IMPORTANT : Nécessaire pour récupérer un byte array en lisant attributeCertificateAttribute et clearance, sinon on ne peut 
		        //pas le lire en tant qu'objet binaire
		        //pour que ca fontionne il faut modifier la syntaxe de attributeCertificateAttribute dans le LDAP en OCTET String : 1.3.6.1.4.1.1466.115.121.1.40
		             
	    try {
	        rlog.doLog(Level.FINE, "ldap.connect", new Object[] { login.toString()});
			ctx = new InitialLdapContext(env, null);  
			rlog.doLog(Level.FINE, "ldap.connectOK", new Object[] {});
	    } catch (NamingException ex) { 
	        rlog.doLog(Level.WARNING, "ldap.incorrectAuthn", new Object[] {ex.getLocalizedMessage(), login.toString()});
	        throw new NamingException(rlog.toString());
	    } 
	}
	
	
	public static ArrayList<LdapName> getUsers(LdapName userstree) throws NamingException {

        ArrayList<LdapName> users = new ArrayList<LdapName>();
        NamingEnumeration answer = null;
        try { answer = ctx.search(userstree.toString(),null); }
        catch (NamingException e) {
        	rlog.doLog(Level.FINE,"ldap.error.user", new Object[] {e.getLocalizedMessage()});
        	throw new NamingException();
        }
        while(answer.hasMore()){
                SearchResult sr = (SearchResult) answer.next();
                LdapName user = new LdapName(sr.getNameInNamespace().toString());
                users.add(user);
                rlog.doLog(Level.FINE,"ldap.user", new Object[] {user});
        }
        return users;
    }
} // class
