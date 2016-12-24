package com.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.CompositeFilter;

import javax.servlet.Filter;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
@EnableOAuth2Client
@RestController
public class SecsimpleApplication extends WebSecurityConfigurerAdapter {

	@SuppressWarnings("SpringJavaAutowiringInspection")
	@Autowired
	OAuth2ClientContext oauth2ClientContext;

	private Filter ssoFilter() {
		CompositeFilter filter = new CompositeFilter();
		List<Filter> filters =new ArrayList<>();
		filters.add(ssoFilter(facebook(),"/login/facebook"));
		filters.add(ssoFilter(github(),"/login/github"));
		filters.add(ssoFilter(diski(),"/login/diskisso"));
		filter.setFilters(filters);
		return filter;
	}

	private Filter ssoFilter(ClientResources client, String path) {
		OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(path);
		OAuth2RestTemplate template = new OAuth2RestTemplate(client.getClient(),oauth2ClientContext);
		filter.setRestTemplate(template);
		filter.setTokenServices(new UserInfoTokenServices(
				client.getResource().getUserInfoUri(),client.getClient().getClientId()));
		return filter;
	}

	@Bean
	@ConfigurationProperties("github")
	public ClientResources github() {
		return new ClientResources();
	}

	@Bean
	@ConfigurationProperties("facebook")
	public ClientResources facebook() {
		return new ClientResources();
	}

	@Bean
	@ConfigurationProperties("diskisso")
	public ClientResources diski() {
		return new ClientResources();
	}

	@Override
	protected  void configure(HttpSecurity http) throws Exception {
		http
				.addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class)
				.antMatcher("/**")
				.authorizeRequests()
					.antMatchers("/","/login**", "/webjars/**").permitAll()
					.anyRequest().authenticated()
				.and().exceptionHandling()
					.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/"))
				.and().logout().logoutSuccessUrl("/").permitAll()
				.and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
				;
	}

	@RequestMapping("/user")
	public Principal user(Principal principal) {
		return principal;
	}

	public static void main(String[] args) {
		SpringApplication.run(SecsimpleApplication.class, args);
	}
}
