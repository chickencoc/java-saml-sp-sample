package saml.sample.sp;

import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.FatalBeanException;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

@SpringBootApplication
public class SamlSpApplication {

    private final static Logger LOGGER = LoggerFactory.getLogger(SamlSpApplication.class);

    public static void main(String[] args) {
        SpringApplication.run(SamlSpApplication.class, args);
    }

    @Configuration
    public static class MvcConfig implements WebMvcConfigurer {
        public void addViewControllers(ViewControllerRegistry registry) {
            //registry.addViewController("/").setViewName("index");
            //registry.addViewController("/main").setViewName("index");
            //registry.addViewController("/user").setViewName("user");
        }
    }

    @Component
    public static class SamlBootstrap implements BeanFactoryPostProcessor {

        private static final Logger LOGGER = LoggerFactory.getLogger(SamlBootstrap.class);

        @Override
        public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {

            try {
                LOGGER.info("Initialize open saml...");
                DefaultBootstrap.bootstrap();
            } catch (ConfigurationException e) {
                throw new FatalBeanException("Error invoking OpenSAML bootstrap", e);
            }
        }
    }

    @Controller
    public static class SamlController {

        @GetMapping({"/", "/main"})
        public String main(HttpServletRequest request, Model model, Authentication authentication) {

            HttpSession session = request.getSession();

            if(authentication != null && authentication.getDetails() != null) {
                model.addAttribute("samlUser", authentication.getDetails());
                model.addAttribute("spSamlString", session.getAttribute("spSamlString"));
                model.addAttribute("idpSamlString", session.getAttribute("idpSamlString"));
            } else {
                model.addAttribute("samlUser", "");
                model.addAttribute("spSamlString", "");
                model.addAttribute("idpSamlString", "");
            }

            /*for(Cookie cookie : request.getCookies()) {
                if( "spLogoutSamlString".equals(cookie.getName()) ) {
                    String value = cookie.getValue();
                    if(StringUtils.hasText(value)) {
                        model.addAttribute("spLogoutSamlString", cookie.getValue());
                    } else {
                        model.addAttribute("spLogoutSamlString", "");
                    }
                }
            }*/

            return "index";
        }

        @GetMapping({"/proxy", "/out"})
        public String proxy() {
            return "redirect:/main";
        }
    }

}