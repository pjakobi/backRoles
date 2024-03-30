package tsn.iam.roles;

import java.text.MessageFormat;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RolesLogger {
	private static ResourceBundle bundle = ResourceBundle.getBundle("messages"); //default locale;
	private static Logger LOGGER;
	private String message="";
	
	public RolesLogger() {
		LOGGER = Logger.getLogger(Thread.currentThread().getStackTrace()[2].getClassName());
	}
	
	public RolesLogger(String className) {
		LOGGER = Logger.getLogger( className );
    } // RolesLogger
	
	public  RolesLogger(String className, Level level, String fmtKey, Object[] params) {
		LOGGER = Logger.getLogger( className );
		MessageFormat formatter = new MessageFormat(bundle.getString(fmtKey));
		message= new MessageFormat(bundle.getString(fmtKey)).format(params);
		LOGGER.log(level, message);
	}
	
	public  RolesLogger(Level level, String fmtKey, Object[] params) {
		LOGGER = Logger.getLogger( Thread.currentThread().getStackTrace()[2].getClassName() );
		MessageFormat formatter = new MessageFormat(bundle.getString(fmtKey));
		message= new MessageFormat(bundle.getString(fmtKey)).format(params);
		LOGGER.log(level, message);
	}
	
	public void doLog(Level level, String fmtKey, Object[] params) {
		message= new MessageFormat(bundle.getString(fmtKey)).format(params);
		LOGGER.log(level, message);
	}
	
	public String toString(String fmtKey, Object[] params) { return message; } 
} // class
