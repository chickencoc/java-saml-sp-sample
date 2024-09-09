package saml.sample.sp;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

final class SamlContextProvider {

    SamlContext getLocalContext(HttpServletRequest request, HttpServletResponse response) {
        SamlContext sct = new SamlContext(request, response);
        return new SamlContext(request, response);
    }
}
