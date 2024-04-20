package tsn.iam.roles;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public record SpifDescriptor(ASN1ObjectIdentifier oid, String name, String file) {

	
	public SpifDescriptor( ASN1ObjectIdentifier oid, String name, String file ) {
		this.oid = oid;
		this.name = name;
		this.file = file;
	} // SpifDescriptor
	

} // record SpifDescriptor
