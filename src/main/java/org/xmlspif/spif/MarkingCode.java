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
 * <p>Java class for markingCode.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="markingCode">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="pageTop"/>
 *     &lt;enumeration value="pageBottom"/>
 *     &lt;enumeration value="pageTopBottom"/>
 *     &lt;enumeration value="documentStart"/>
 *     &lt;enumeration value="documentEnd"/>
 *     &lt;enumeration value="noNameDisplay"/>
 *     &lt;enumeration value="noMarkingDisplay"/>
 *     &lt;enumeration value="suppressClassName"/>
 *     &lt;enumeration value="firstLineOfText"/>
 *     &lt;enumeration value="lastLineOfText"/>
 *     &lt;enumeration value="subject"/>
 *     &lt;enumeration value="xHeader"/>
 *     &lt;enumeration value="portionMarking"/>
 *     &lt;enumeration value="inputTitle"/>
 *     &lt;enumeration value="waterMark"/>
 *     &lt;enumeration value="replacePolicy"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "markingCode")
@XmlEnum
public enum MarkingCode {

    @XmlEnumValue("pageTop")
    PAGE_TOP("pageTop"),
    @XmlEnumValue("pageBottom")
    PAGE_BOTTOM("pageBottom"),
    @XmlEnumValue("pageTopBottom")
    PAGE_TOP_BOTTOM("pageTopBottom"),
    @XmlEnumValue("documentStart")
    DOCUMENT_START("documentStart"),
    @XmlEnumValue("documentEnd")
    DOCUMENT_END("documentEnd"),
    @XmlEnumValue("noNameDisplay")
    NO_NAME_DISPLAY("noNameDisplay"),
    @XmlEnumValue("noMarkingDisplay")
    NO_MARKING_DISPLAY("noMarkingDisplay"),
    @XmlEnumValue("suppressClassName")
    SUPPRESS_CLASS_NAME("suppressClassName"),
    @XmlEnumValue("firstLineOfText")
    FIRST_LINE_OF_TEXT("firstLineOfText"),
    @XmlEnumValue("lastLineOfText")
    LAST_LINE_OF_TEXT("lastLineOfText"),
    @XmlEnumValue("subject")
    SUBJECT("subject"),
    @XmlEnumValue("xHeader")
    X_HEADER("xHeader"),
    @XmlEnumValue("portionMarking")
    PORTION_MARKING("portionMarking"),
    @XmlEnumValue("inputTitle")
    INPUT_TITLE("inputTitle"),
    @XmlEnumValue("waterMark")
    WATER_MARK("waterMark"),
    @XmlEnumValue("replacePolicy")
    REPLACE_POLICY("replacePolicy");
    private final String value;

    MarkingCode(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static MarkingCode fromValue(String v) {
        for (MarkingCode c: MarkingCode.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
