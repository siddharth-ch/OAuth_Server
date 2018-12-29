package com.sid.secure.oauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

@EnableAuthorizationServer
@Configuration
public class OauthServer extends AuthorizationServerConfigurerAdapter {
    @Autowired
    public BCryptPasswordEncoder passwordEncoder() {
	return new BCryptPasswordEncoder();
    }

    @Autowired
    @Qualifier("authenticationManagerBean")
    private AuthenticationManager authenticationManager;

    @Bean
    public TokenStore tokenStore() {
	return new JwtTokenStore(jwtTokenEnhancer());
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
	endpoints.tokenStore(tokenStore()).tokenEnhancer(jwtTokenEnhancer())
		.authenticationManager(authenticationManager);
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
	clients.inMemory().withClient("client1")//
		.secret(passwordEncoder().encode("secret")).scopes("API")//
		.autoApprove(true)//
		.authorities("API_READ", "API_WRITE")//
		.authorizedGrantTypes("implicit", "refresh_token", "client_credentials", "password",
			"authorization_code")
		.accessTokenValiditySeconds(1 * 60 * 60).refreshTokenValiditySeconds(6 * 60 * 60);
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
	security.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()").realm("API_JWT_REALM");
    }

    @Bean
    protected JwtAccessTokenConverter jwtTokenEnhancer() {
	KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"),
		"mySecretKey".toCharArray());
	JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
	converter.setKeyPair(keyStoreKeyFactory.getKeyPair("jwt"));
	return converter;
    }

}
