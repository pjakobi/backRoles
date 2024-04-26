package tsn.iam.roles;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.DependsOn;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.naming.InvalidNameException;
import javax.naming.NamingException;
import javax.naming.ldap.LdapName;

@Slf4j
@Component
public class LdapService {
	@Autowired private Environment env;
	private LdapConfig cfg = null;
	private LdapConnection cnx = null;
	

	@PostConstruct
    private void postConstruct() throws FileNotFoundException, URISyntaxException, IOException, NamingException {
		ResourceBundle bundle = ResourceBundle.getBundle("messages");
		Props properties = new Props(env);
		cfg = new LdapConfig();
		URI uri = cfg.getLdapUri(properties.getStringLdapConfigFile());
    	LdapName bindDn = cfg.getLdapBindDn(properties.getStringLdapConfigFile());
    	String pwd = cfg.getLdapBindPassword(properties.getPwFname());
    	cnx = new LdapConnection(uri, bindDn, pwd);
    	
	} // postConstruct
	
	@PreDestroy
    public void preDestroy() { cnx.close(); }
	
	LdapConnection getCnx() { return cnx; }
} // LdapService
