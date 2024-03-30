package tsn.iam.roles;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.logging.Level;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

public class LdapConfig {
	RolesLogger rlog = new RolesLogger();
	BufferedReader reader;
	
	private void getReader(String fileName) throws FileNotFoundException {
		try { reader = new BufferedReader(new FileReader(fileName));
		} catch (FileNotFoundException e) {
			rlog.doLog(Level.WARNING, "ldap.invalidFile", new Object[] {fileName});
			throw new FileNotFoundException(rlog.toString());
		}
	}
	
	// Decode uri : [scheme (ldap)]://hostname[:port]
	private URI decodeUri(String value) throws URISyntaxException
	{
		String scheme = "ldap";
		String hostPort;
		String hostName = "";
		String port = "389";
		// Is there a scheme ?
		String[] tokens=value.split("://");
		if (tokens.length > 1) { 
			if (!(tokens[0].equals("ldap"))) { // invalid scheme
				rlog.doLog(Level.WARNING,"ldap.invUriSyntax", new Object[] {"value", tokens[0]});
				throw new URISyntaxException(rlog.toString(),"");
			} // if
			hostPort = tokens[1];
		} else hostPort = value; // if
		
		// hostPort can be an FQDN or FQDN:port
		tokens = hostPort.split(":");
		hostName = tokens[0];
		if (tokens.length > 1) port = tokens[1]; // FQDN:port
		return new URI(scheme + "://" + hostName + ":" + port);
	} // decodeUri
	
	// Forced return value to "localhost:389"
	public URI getLdapUri(String fileName) throws FileNotFoundException, URISyntaxException, IOException {
		// ldap:// + <server> + : + <port>
		String server="localhost";
		String strPort="389";
		URI uri = null;
		getReader(fileName);
		try {
			for(String line; (line = reader.readLine()) != null; )
			{
				String[] tokens = line.split("\t");
				if (tokens[0].equals("#")|| (tokens.length < 2)) continue;
				if (tokens[0].startsWith("#")) continue;
				if (tokens[0].equals("URI")) {
					try { // Is there a port in tokens[1] ? - check if ":" in string
						uri = decodeUri(tokens[1]);
						return uri;
					} catch (URISyntaxException e) {
						rlog.doLog(Level.FINE,"ldap.invUriSyntax", new Object[] {fileName, tokens[1]});	
						throw new URISyntaxException(fileName,e.getLocalizedMessage());
					}
				}
				// URI not found - is there a HOST ?	
				if (tokens[0].equals("HOST")) {
					String[] serverPort = tokens[1].split(":"); // server:port
					server = serverPort[0];
					if (serverPort.length > 1) strPort = serverPort[1];
				}
				
				if (tokens[0].equals("PORT")) {
					strPort = tokens[1];				
				}
			} // for
			return new URI("ldap://" + server + ":" + strPort); 
		} catch (IOException e) {
			rlog.doLog(Level.WARNING, "ldap.ioError", new Object[] {fileName});
			throw new IOException(e.getLocalizedMessage());
		} catch (URISyntaxException e) {
			rlog.doLog(Level.WARNING, "ldap.invalidFile", new Object[] {uri.toString()});
			throw new URISyntaxException(rlog.toString(), "");
		}
	} // getLdapUri
	
	
	LdapName getLdapBindDn(String fileName) throws InvalidNameException, IOException, FileNotFoundException {
		String result=null;
		getReader(fileName);
		try {
			for(String line; (line = reader.readLine()) != null; )
			{
				String[] tokens = line.split("[ \t]");
				if (tokens[0].startsWith("#")) continue;
				if ((tokens[0] == null) || (tokens.length < 2)) continue;
				if (tokens[0].equals("BINDDN")) return new LdapName(tokens[1]);
			}
		} catch (InvalidNameException e) {
			rlog.doLog(Level.WARNING, "ldap.invalidName", new Object[] {fileName, "BINDDN", result});
			throw new InvalidNameException(e.getLocalizedMessage());
		} catch (IOException e) {
			rlog.doLog(Level.WARNING, "ldap.ioError", new Object[] {fileName});
			throw new IOException(e.getLocalizedMessage());
		}
		return new LdapName(result);
	} // getLdapBindDn
	
	
	public String getLdapBindPassword(String fileName) throws IOException {
		String line;
		getReader(fileName);
		try { line = reader.readLine(); }
		catch (IOException e) {
			rlog.doLog(Level.WARNING, "ldap.ioError", new Object[] {fileName});
			throw new IOException(e.getLocalizedMessage());
		}
		String[] tokens = line.split(" ");
		if (tokens.length > 0) return tokens[0];
		// No password in pwFname
		rlog.doLog(Level.WARNING, "ldap.error.password", new Object[] {fileName}); 
		throw new SecurityException(rlog.toString());
	} // getLdapBindPassword
}
