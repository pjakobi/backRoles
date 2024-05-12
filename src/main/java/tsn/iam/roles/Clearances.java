package tsn.iam.roles;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class Clearances {
	private ASN1ObjectIdentifier oid;
	private List<ClassificationDescriptor> descriptors = new ArrayList<ClassificationDescriptor>();
	
	public Clearances(ASN1ObjectIdentifier oid) { this.oid = oid; }
	
	public ASN1ObjectIdentifier getOid() { return this.oid; }
	public List<ClassificationDescriptor> getDescriptors() { return this.descriptors; }
	
	public void setOid(ASN1ObjectIdentifier oid) { this.oid = oid; }
	public void setDescriptors(List<ClassificationDescriptor> descriptors) { this.descriptors = descriptors; }
}
