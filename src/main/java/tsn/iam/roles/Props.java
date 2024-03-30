package tsn.iam.roles;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import lombok.Getter;



@Getter 

public class Props {
	@Autowired	private Environment env;
	private String searchBase;
	private String userstree;
	private String treeroot;
	private String counterFile;
	private String acBase;
	private String spifPath;
	private String stringLdapConfigFile;
	private String pwFname;
	private String usersSubTree;
	private String acSubTree;
	
	public Props(Environment env) {
		searchBase = env.getProperty("ac.base");
		userstree = env.getProperty("ldap.userstree");
		treeroot = env.getProperty("ldap.treeroot");
		counterFile = env.getProperty("ac.counter");
		acBase = env.getProperty("ac.base");
		spifPath = env.getProperty("spif.path");
		stringLdapConfigFile = env.getProperty("ldap.file");
		pwFname = env.getProperty("ldap.pwfile");
		usersSubTree = userstree + "," + treeroot;
		acSubTree = searchBase + "," + treeroot;
	}
} // class Properties
