package saml.sample.sp;

import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.core.NameID;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;

import java.io.StringWriter;
import java.io.Writer;
import java.util.List;

final class SamlUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(SamlUtil.class);

    static String getStringFromXMLObject(XMLObject xmlObj) {
        if (xmlObj instanceof XSString) {
            return ((XSString) xmlObj).getValue();
        } else if (xmlObj instanceof XSAny) {
            XSAny xsAny = (XSAny) xmlObj;
            String textContent = xsAny.getTextContent();
            if (StringUtils.hasText(textContent)) {
                return textContent;
            }
            List<XMLObject> unknownXMLObjects = xsAny.getUnknownXMLObjects();
            if (!CollectionUtils.isEmpty(unknownXMLObjects)) {
                XMLObject xmlObject = unknownXMLObjects.get(0);
                if (xmlObject instanceof NameID) {
                    NameID nameID = (NameID) xmlObject;
                    return nameID.getValue();
                }
            }
        }
        return "";
    }

    static String samlObjectToString(SAMLObject object) {
        try {
            Element ele = samlObjectToElement(object);
            return elementToString(ele);
        } catch (MarshallingException | IllegalArgumentException e) {
            LOGGER.warn("Failed to SAMLObject to String.", e);
            return "";
        }
    }

    private static Element samlObjectToElement(SAMLObject object) throws MarshallingException {
        Element element = null;
        try {
            MarshallerFactory unMarshallerFactory = Configuration.getMarshallerFactory();
            Marshaller marshaller = unMarshallerFactory.getMarshaller(object);
            element = marshaller.marshall(object);
        } catch (ClassCastException e) {
            throw new IllegalArgumentException("The class does not implement the interface XMLObject", e);
        }
        return element;
    }

    private static String elementToString(Element ele) {
        Document document = ele.getOwnerDocument();
        DOMImplementationLS domImplLS = (DOMImplementationLS) document.getImplementation();
        LSOutput lsOutput = domImplLS.createLSOutput();
        // xml utf-8로 변경 ----
        lsOutput.setEncoding("UTF-8");

        Writer writer = new StringWriter();
        lsOutput.setCharacterStream(writer);

        LSSerializer serializer = domImplLS.createLSSerializer();
        serializer.write(ele, lsOutput);
        // xml utf-8로 변경 ----
        return writer.toString();
    }

    static void setInSession(String key, Object value) {
        ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest()
                .getSession()
                .setAttribute(key, value);
    }

    static Object getInSession(String key) {
        return ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest()
                .getSession()
                .getAttribute(key);
    }
}