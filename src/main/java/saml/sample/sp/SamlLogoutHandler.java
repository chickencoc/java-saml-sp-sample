package saml.sample.sp;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;
import java.util.UUID;

/**
 * security logout handler의 logout mehtod 활용해서 logout 로직 작성
 * WebSecurityConfigurer에 logoutHandler로 등록
 */
public class SamlLogoutHandler extends SecurityContextLogoutHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(SamlLogoutHandler.class);

    @Value("${sp.entity_id}")
    private String entityId;

    @Value("${sp.acs}")
    private String acs;

    @Value("${sp.single_logout_service_location}")
    private String ssoLogoutLocation;

    @Value("${sp.login_url}")
    private String loginUrl;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        // saml context 생성
        try {
            BasicSAMLMessageContext<SAMLObject, LogoutRequest, SAMLObject> context = new BasicSAMLMessageContext<>();
            HttpServletResponseAdapter transport = new HttpServletResponseAdapter(response, false);
            context.setOutboundMessageTransport(transport);
            context.setPeerEntityEndpoint(getIDPEndpoint());

            Issuer issuer = buildIssuer(entityId);
            // agent base url
            String defaultUrl = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort();
            LogoutRequest logoutRequest = buildLogoutRequest(defaultUrl, issuer);

            // sp saml string - logout
            String samlString = SamlUtil.samlObjectToString(logoutRequest);
            LOGGER.debug("Created LogoutRequest[{}]", samlString);
            // store in a session
            // SamlUtil.setInSession("spSamlString", samlString);

            context.setOutboundSAMLMessage(logoutRequest);

            // redirect
            HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
            encoder.encode(context);

            // session, authentication 만료 시킴
            super.logout(request, response, authentication);

            /*Cookie cookie = new Cookie("spLogoutSamlString", samlString);
            cookie.setPath("/");
            response.addCookie(cookie);*/
        } catch (MessageEncodingException e) {
            LOGGER.error("Error initializing SAML Request", e);
            // 에러처리를 어떻게 해야할까????? SecurityContextLogoutHandler의 logout을 override 하지말기?
            // throw new ServletException(e);
        }
    }

    @SuppressWarnings("unchecked")
    private <T> T buildSAMLObject(final Class<T> objectClass, QName qName) {
        XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
        return (T) builderFactory.getBuilder(qName).buildObject(qName);
    }

    private LogoutRequest buildLogoutRequest(String acsUrl, Issuer issuer) {
        LogoutRequest logoutRequest = buildSAMLObject(LogoutRequest.class, LogoutRequest.DEFAULT_ELEMENT_NAME);
        logoutRequest.setVersion(SAMLVersion.VERSION_20);
        logoutRequest.setIssuer(issuer);
        logoutRequest.setIssueInstant(new DateTime());
        logoutRequest.setID(UUID.randomUUID().toString());
        logoutRequest.setNameID(getNameID());
        logoutRequest.setDestination(ssoLogoutLocation);
        logoutRequest.getSessionIndexes().add(buildSessionIndexByIdpToken());
        return logoutRequest;
    }

    private Issuer buildIssuer(String issuingEntityName) {
        Issuer issuer = buildSAMLObject(Issuer.class, Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue(issuingEntityName);
        issuer.setFormat(NameIDType.ENTITY);
        return issuer;
    }

    private Endpoint getIDPEndpoint() {
        Endpoint samlEndpoint = buildSAMLObject(Endpoint.class, SingleLogoutService.DEFAULT_ELEMENT_NAME);
        samlEndpoint.setLocation(ssoLogoutLocation);
        return samlEndpoint;
    }

    private NameID getNameID() {
        NameID nameID = buildSAMLObject(NameID.class, NameID.DEFAULT_ELEMENT_NAME);
        return nameID;
    }

    /**
     * 제목 : SAML 2.0 LogoutRequest should contain session indexes
     * sso server에서 사용자 authToken을 idp response의 id로 보내줌.
     * 그걸 sso server에서 logout 시 sessionIndex에서 꺼내서 확인 후 agt_session을 삭제해서 사용자를 로그아웃 시킴
     * 참고 : https://github.com/spring-projects/spring-security/issues/10613
     */
    private SessionIndex buildSessionIndexByIdpToken() {
        SessionIndex sessionIndex = buildSAMLObject(SessionIndex.class, SessionIndex.DEFAULT_ELEMENT_NAME);
        sessionIndex.setSessionIndex( (String) SamlUtil.getInSession("idpToken") );
        return sessionIndex;
    }
}
