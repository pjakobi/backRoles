package tsn.iam.roles;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.xmlspif.spif.ObjectIdData;

public record SpifDescriptor(ASN1ObjectIdentifier oid, String Name) {

}
