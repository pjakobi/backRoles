package tsn.iam.roles;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.StringTokenizer;
import java.util.logging.Level;

import javax.naming.InvalidNameException;
import javax.naming.NamingException;
import javax.naming.directory.ModificationItem;
import javax.naming.ldap.LdapName;

import org.springframework.web.server.ServerErrorException;

public class SerialNumber {
    private static final String className = SerialNumber.class.getName();
    private static RolesLogger rlog=new RolesLogger(className);
    private final static BigInteger ONE = BigInteger.ONE;
	private BigInteger currentSerialNumber;
	/**
     * A serial number counter is implemented as an attribute of the AC requests subtree.
     * @param DN is the counter DN.
     * Usinq ldapmodify provides a means to avoid concurrent accesses.
	 * @throws NamingException (counter DN invalid)
	 * @throws NumberFormatException : serialNumberRetries is not a number (config. fault)
	 * @throws InterruptedException : should not happen (internal error)
     * 
     */
	public SerialNumber(LdapName dn) throws NumberFormatException, NamingException, InterruptedException {
		BigInteger currentSerialNumber,newSerialNumber=null;
		rlog.doLog(Level.FINE,"spif.setACBaseCounterOK", new Object[] {dn.toString()});
		for (int retries=0; retries < Constants.serialNumberRetries; retries++) {
			try { currentSerialNumber = JndidapAPI.getSerialNum(dn);}
			catch (NamingException e) { throw new InvalidNameException(e.getLocalizedMessage()); } // should not happen, internal error

			newSerialNumber = currentSerialNumber.add(BigInteger.ONE);
			try {
				JndidapAPI.setSerialNum(dn,newSerialNumber);
				return; // OK
			} catch (NamingException e) { // May be caused by a concurrent access : retry after a while in that case
					Thread.sleep(Constants.serialNumberSleepValue); 
					continue; // try again
			}
		} // while
		rlog.doLog(Level.FINE,"spif.setACBaseCounterNOK", new Object[] {newSerialNumber.toString()}); // retries exhausted
		throw new ServerErrorException(rlog.toString(), null);
	} // SerialNumber
	
	public BigInteger get() { return currentSerialNumber; }
	
} // class SerialNumber
