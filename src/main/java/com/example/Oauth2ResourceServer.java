package com.example;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;

@Configuration
public class Oauth2ResourceServer {

//    @Configuration @Order(10)
//    protected static class NonOauthResources extends WebSecurityConfigurerAdapter {
//
//        @Override
//        protected void configure(HttpSecurity http) throws Exception {
//            http.authorizeRequests()
//                    .antMatchers("/api/halo").permitAll()
//                    .antMatchers("/api/state/**").permitAll()
//                    .antMatchers("/**").permitAll()
//                    .and().anonymous();
//        }
//    }

    @Configuration
    @EnableResourceServer
    protected static class ResourceServerConfiguration extends
            ResourceServerConfigurerAdapter {
    	
    	@Value("${diskisso.client.resourceId}")
        private String resourceId;
    	
    	@Value("${diskisso.client.clientId}")
        private String clientId;
    	
    	@Value("${diskisso.client.clientSecret}")
        private String clientSecret;
    	
    	@Value("${diskisso.client.endPointUrl}")
        private String endPointUrl;

        @Override
        public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
            RemoteTokenServices tokenService = new RemoteTokenServices();
            tokenService.setClientId(clientId);
            tokenService.setClientSecret(clientSecret);
            tokenService.setCheckTokenEndpointUrl(endPointUrl);
            
            resources
                    .resourceId(resourceId)
                    .tokenServices(tokenService);
        }

        @Override
        public void configure(HttpSecurity http) throws Exception {
            http.authorizeRequests()
                    .antMatchers("/api/staff").hasRole("USER")
                    .antMatchers("/api/client").access("#oauth2.hasScope('trust')")
                    .antMatchers("/api/admin").hasRole("ADMIN");
        }

    }

}
