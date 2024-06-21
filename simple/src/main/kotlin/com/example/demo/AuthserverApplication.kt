package com.example.demo

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.MediaType
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.core.oidc.OidcUserInfo
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher
import org.springframework.stereotype.Service
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*


@SpringBootApplication
class AuthserverApplication

fun main(args: Array<String>) {
    runApplication<AuthserverApplication>(*args)
}

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
class SecurityConfig {

    @Bean
    @Order(1)
    fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)

        http.getConfigurer(OAuth2AuthorizationServerConfigurer::class.java)
            .oidc { }  // Enable OpenID Connect 1.0
        http
            // Redirect to the login page when not authenticated from the
            // authorization endpoint
            .exceptionHandling {
                it.defaultAuthenticationEntryPointFor(
                    LoginUrlAuthenticationEntryPoint("/login"),
                    MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
            }
            // Accept access tokens for User Info and/or Client Registration
            .oauth2ResourceServer { it.jwt { } }

        return http.build()
    }

    @Bean
    @Order(2)
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeHttpRequests { authorize(anyRequest, authenticated) }
            // Form login handles the redirect to the login page from the
            // authorization server filter chain
            formLogin { }
        }

        return http.build()
    }


    @Bean
    fun userDetailsService(): UserDetailsService {
        val userDetails = User.withDefaultPasswordEncoder()
            .username("demouser")
            .password("password")
            .roles("DEMO_USER")
            .build()

        return InMemoryUserDetailsManager(userDetails)
    }

    @Bean
    fun registeredClientRepository(): RegisteredClientRepository {
        val demoClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("demo-client")
            .clientSecret("{noop}password")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri("http://127.0.0.1:3000")
            .postLogoutRedirectUri("http://127.0.0.1:3000")
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .clientSettings(
                ClientSettings.builder().requireAuthorizationConsent(true)
                    .settings { it["aud"] = "http://demo-service" }
                    .build()
            )
            .build()

        return InMemoryRegisteredClientRepository(demoClient)
    }

    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val keyPair = generateRsaKey()
        val publicKey = keyPair.public as RSAPublicKey
        val privateKey = keyPair.private as RSAPrivateKey
        val rsaKey = RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build();
        val jwkSet = JWKSet(rsaKey);
        return ImmutableJWKSet(jwkSet)
    }

    private fun generateRsaKey(): KeyPair {
        lateinit var keyPair: KeyPair
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(2048)
            keyPair = keyPairGenerator.generateKeyPair()
        } catch (ex: Exception) {
            throw IllegalStateException(ex)
        }
        return keyPair
    }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings {
        return AuthorizationServerSettings.builder().build()
    }

    @Bean
    fun jwtTokenCustomizer(userInfoService: OidcUserInfoService): OAuth2TokenCustomizer<JwtEncodingContext> {
        return OAuth2TokenCustomizer { context ->
            if (OAuth2TokenType.ACCESS_TOKEN == context.tokenType) {
                context.claims
                    .claims { claims ->
                        val authentiocation = context.getPrincipal<Authentication>()
                        val roles = AuthorityUtils
                            .authorityListToSet(authentiocation.authorities)
                            .stream()
                            .map { it.replaceFirst("^ROLE_".toRegex(), "") }
                            .toList()
                        claims["roles"] = roles

                        // add client aud to access token
                        claims["aud"] = context.registeredClient.clientSettings.settings["aud"] as String

                        // add user info field to access token
                        val userInfo: OidcUserInfo = userInfoService.loadUser(authentiocation.name)
                        claims["dob"] = userInfo.claims["dob"]
                    }

//                if (OidcParameterNames.ID_TOKEN == context.tokenType.value) {
//                    val userInfo: OidcUserInfo = userInfoService.loadUser(
//                        context.getPrincipal().getName()
//                    )
//                    context.claims.claims { claims -> claims.putAll(userInfo.claims.) }
//                }
            }
        }
    }

}

@Service
class OidcUserInfoService {
    private val userInfoRepository = UserInfoRepository()

    fun loadUser(username: String): OidcUserInfo {
        return OidcUserInfo(userInfoRepository.findByUsername(username))
    }

    internal class UserInfoRepository {
        private var userInfo: Map<String, Map<String, Any>> = emptyMap()

        init {
            userInfo = mapOf(
                "demouser" to createUser("user1"),
                "user2" to createUser("user2")
            )
        }

        fun findByUsername(username: String): Map<String, Any> {
            return userInfo[username]!!
        }

        private fun createUser(username: String): Map<String, Any> {
            return OidcUserInfo.builder()
                .subject(username)
                .name("First Last")
                .givenName("First")
                .familyName("Last")
                .middleName("Middle")
                .nickname("User")
                .preferredUsername(username)
                .profile("https://example.com/$username")
                .picture("https://example.com/$username.jpg")
                .website("https://example.com")
                .email("$username@example.com")
                .emailVerified(true)
                .gender("female")
                .birthdate("1970-01-01")
                .zoneinfo("Europe/Paris")
                .locale("en-US")
                .phoneNumber("+1 (604) 555-1234;ext=5678")
                .phoneNumberVerified(false)
                .claim(
                    "address",
                    mapOf("formatted" to "Champ de Mars\n5 Av. Anatole France\n75007 Paris\nFrance")
                )
                // add custom attributes
                .claim("dob", "1990-12-31")
                .updatedAt("1970-01-01T00:00:00Z")
                .build()
                .claims
        }
    }
}