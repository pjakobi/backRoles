//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2022.05.01 at 12:18:02 PM CEST 
//


package org.xmlspif.spif;

import jakarta.xml.bind.annotation.XmlEnum;
import jakarta.xml.bind.annotation.XmlEnumValue;
import jakarta.xml.bind.annotation.XmlType;


/**
 * <p>Java class for qualifierCode.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="qualifierCode">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="prefix"/>
 *     &lt;enumeration value="suffix"/>
 *     &lt;enumeration value="separator"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "qualifierCode")
@XmlEnum
public enum QualifierCode {

    @XmlEnumValue("prefix")
    PREFIX("prefix"),
    @XmlEnumValue("suffix")
    SUFFIX("suffix"),
    @XmlEnumValue("separator")
    SEPARATOR("separator");
    private final String value;

    QualifierCode(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static QualifierCode fromValue(String v) {
        for (QualifierCode c: QualifierCode.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
