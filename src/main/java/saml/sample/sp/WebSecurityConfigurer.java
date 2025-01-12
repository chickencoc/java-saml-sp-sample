package saml.sample.sp;

import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.SessionCookieConfig;
import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigurer extends WebSecurityConfigurerAdapter {

    @Value("${sp.acs}")
    private String acs;

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // login config
        http.formLogin().disable()
                .authorizeRequests()
                .antMatchers("/", "/main", "/out", "/error", acs + "/**").permitAll()
                .anyRequest().authenticated()
                .and()
            .httpBasic()
                .authenticationEntryPoint(samlSsoEntryPoint())
                .and()
            .addFilterAfter(samlFilterChain(), BasicAuthenticationFilter.class)
            .csrf().disable();

        // logout config
        http.logout()
                .logoutUrl("/logout")
                .addLogoutHandler(samlLogoutHandler())
                .logoutSuccessUrl("/main");
    }

    @Override
    public void configure(AuthenticationManagerBuilder authBuilder) {
        authBuilder.authenticationProvider(authenticationProvider());
    }

    @Bean
    public ServletContextInitializer servletContextInitializer() {
        return servletContext -> {
            SessionCookieConfig sessionCookieConfig = servletContext.getSessionCookieConfig();
            sessionCookieConfig.setName("SP.SESSION");
            sessionCookieConfig.setHttpOnly(true);
        };
    }

    @Bean
    public FilterChainProxy samlFilterChain() throws Exception {
        List<SecurityFilterChain> chains = new ArrayList<>();
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher(acs + "/**"), samlFilter()));
        return new FilterChainProxy(chains);
    }

    @Bean
    public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
        SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successRedirectHandler.setDefaultTargetUrl("/main");
        return successRedirectHandler;
    }

    @Bean
    public SamlAssertionConsumeFilter samlFilter() throws Exception {
        SamlAssertionConsumeFilter samlFilter = new SamlAssertionConsumeFilter(acs);
        samlFilter.samlContextProvider(samlContextProvider());
        samlFilter.setAuthenticationManager(authenticationManagerBean());
        samlFilter.setAuthenticationSuccessHandler(successRedirectHandler());
        return samlFilter;
    }

    @Bean
    public SamlContextProvider samlContextProvider() {
        return new SamlContextProvider();
    }

    @Bean
    public SamlSsoEntryPoint samlSsoEntryPoint() {
        return new SamlSsoEntryPoint();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new SamlAuthenticationProvider().assertionConsumer(assertionConsumer());
    }

    @Bean
    public SimpleSamlAssertionConsumer assertionConsumer() {
        return new SimpleSamlAssertionConsumer();
    }

    /**
     * bean에 등록하지 않으면 application.yml의 값을 field에 주입하지 못함
     * 이유 : @Value가 bean factory annotaion이기 때문, bean 생성될 때 field 주입 해줌.
     */
    @Bean
    public SamlLogoutHandler samlLogoutHandler() {
        return new SamlLogoutHandler();
    }

    @Bean(initMethod = "initialize")
    public ParserPool parserPool() {
        return new StaticBasicParserPool();
    }
}