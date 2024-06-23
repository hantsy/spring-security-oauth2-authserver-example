package org.springframework.security.oauth2.server.authorization.authentication

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClaimAccessor
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator
import java.security.Principal
import java.util.stream.Collectors


class OAuth2ResourceOwnerPasswordAuthenticationProvider(
    private val authenticationManager: AuthenticationManager,
    private val authorizationService: OAuth2AuthorizationService,
    private val tokenGenerator: OAuth2TokenGenerator<out OAuth2Token>
) : AuthenticationProvider {

    companion object {
        private val LOGGER: Logger =
            LoggerFactory.getLogger(OAuth2ResourceOwnerPasswordAuthenticationProvider::class.java)
        private const val ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2"
        private val ID_TOKEN_TOKEN_TYPE = OAuth2TokenType(OidcParameterNames.ID_TOKEN)
    }

    @Throws(AuthenticationException::class)
    override fun authenticate(authentication: Authentication): Authentication {
        val resourceOwnerPasswordAuthentication = authentication as OAuth2ResourceOwnerPasswordAuthenticationToken

        val clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(resourceOwnerPasswordAuthentication)

        val registeredClient = clientPrincipal.registeredClient
            ?: throw OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT)

        if (!registeredClient.authorizationGrantTypes.contains(AuthorizationGrantType.PASSWORD)) {
            throw OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT)
        }

        val usernamePasswordAuthentication = getUsernamePasswordAuthentication(resourceOwnerPasswordAuthentication)

        var authorizedScopes = registeredClient.scopes // Default to configured scopes
        val requestedScopes = resourceOwnerPasswordAuthentication.scopes
        if (requestedScopes.isNotEmpty()) {
            val unauthorizedScopes = requestedScopes.stream()
                .filter { requestedScope: String? ->
                    !registeredClient.scopes.contains(requestedScope)
                }
                .collect(Collectors.toSet())
            if (unauthorizedScopes.isNotEmpty()) {
                throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE)
            }

            authorizedScopes = LinkedHashSet(requestedScopes)
        }

        if (LOGGER.isTraceEnabled) {
            LOGGER.trace("Validated token request parameters")
        }

        // @formatter:off
        val tokenContextBuilder = DefaultOAuth2TokenContext.builder()
            .registeredClient(registeredClient)
            .principal(usernamePasswordAuthentication)
            .authorizationServerContext(AuthorizationServerContextHolder.getContext())
            .authorizedScopes(authorizedScopes)
            .authorizationGrantType(AuthorizationGrantType.PASSWORD)
            .authorizationGrant(resourceOwnerPasswordAuthentication)
        // @formatter:on

        // ----- Access token -----
        var tokenContext: OAuth2TokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build()
        val generatedAccessToken = tokenGenerator.generate(tokenContext)
        if (generatedAccessToken == null) {
            val error = OAuth2Error(
                OAuth2ErrorCodes.SERVER_ERROR,
                "The token generator failed to generate the access token.", ERROR_URI
            )
            throw OAuth2AuthenticationException(error)
        }

        if (LOGGER.isTraceEnabled) {
            LOGGER.trace("Generated access token")
        }

        val accessToken = OAuth2AccessToken(
            TokenType.BEARER,
            generatedAccessToken.tokenValue,
            generatedAccessToken.issuedAt,
            generatedAccessToken.expiresAt,
            tokenContext.authorizedScopes
        )

        // @formatter:off
        val authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
            .principalName(usernamePasswordAuthentication.name)
            .authorizationGrantType(AuthorizationGrantType.PASSWORD)
            .authorizedScopes(authorizedScopes)
            .attribute(Principal::class.java.name, usernamePasswordAuthentication)
        // @formatter:on

        if (generatedAccessToken is ClaimAccessor) {
            authorizationBuilder.token(accessToken) {
                it[Token.CLAIMS_METADATA_NAME] = generatedAccessToken.claims
            }
        } else {
            authorizationBuilder.accessToken(accessToken)
        }

        // ----- Refresh token -----
        var refreshToken: OAuth2RefreshToken? = null
        if (registeredClient.authorizationGrantTypes.contains(AuthorizationGrantType.REFRESH_TOKEN) &&  // Do not issue refresh token to public client
            clientPrincipal.clientAuthenticationMethod != ClientAuthenticationMethod.NONE
        ) {
            tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build()
            val generatedRefreshToken = tokenGenerator.generate(tokenContext)
            if (generatedRefreshToken !is OAuth2RefreshToken) {
                val error = OAuth2Error(
                    OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the refresh token.",
                    ERROR_URI
                )
                throw OAuth2AuthenticationException(error)
            }

            if (LOGGER.isTraceEnabled) {
                LOGGER.trace("Generated refresh token")
            }

            refreshToken = generatedRefreshToken
            authorizationBuilder.refreshToken(refreshToken)
        }

        // ----- ID token -----
        var idToken: OidcIdToken? = null
        if (requestedScopes.contains(OidcScopes.OPENID)) {

            // @formatter:off
            tokenContext = tokenContextBuilder
                .tokenType(ID_TOKEN_TOKEN_TYPE)
                .authorization(authorizationBuilder.build()) // ID token customizer may need access to the access token and/or refresh token
                .build()
            // @formatter:on

            val generatedIdToken = tokenGenerator.generate(tokenContext)
            if (generatedIdToken !is Jwt) {
                val error = OAuth2Error(
                    OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the ID token.",
                    ERROR_URI
                )
                throw OAuth2AuthenticationException(error)
            }

            if (LOGGER.isTraceEnabled) {
                LOGGER.trace("Generated id token")
            }

            idToken = OidcIdToken(
                generatedIdToken.tokenValue,
                generatedIdToken.issuedAt,
                generatedIdToken.expiresAt,
                generatedIdToken.claims
            )
            authorizationBuilder.token(idToken) {
                it[Token.CLAIMS_METADATA_NAME] = idToken.claims
            }
        }

        val authorization = authorizationBuilder.build()
        authorizationService.save(authorization)

        val additionalParameters: MutableMap<String, Any> = mutableMapOf()
        if (idToken != null) {
            additionalParameters[OidcParameterNames.ID_TOKEN] = idToken.tokenValue
        }

        if (LOGGER.isTraceEnabled) {
            LOGGER.trace("Authenticated token request")
        }

        return OAuth2AccessTokenAuthenticationToken(
            registeredClient,
            clientPrincipal,
            accessToken,
            refreshToken,
            additionalParameters
        )
    }

    override fun supports(authentication: Class<*>): Boolean =
        OAuth2ResourceOwnerPasswordAuthenticationToken::class.java.isAssignableFrom(authentication)

    private fun getUsernamePasswordAuthentication(resourceOwnerPasswordAuthentication: OAuth2ResourceOwnerPasswordAuthenticationToken): Authentication {
        val username = resourceOwnerPasswordAuthentication.username
        val password = resourceOwnerPasswordAuthentication.password

        val usernamePasswordAuthenticationToken = UsernamePasswordAuthenticationToken(username, password)
        LOGGER.debug("got usernamePasswordAuthenticationToken=$usernamePasswordAuthenticationToken")

        val usernamePasswordAuthentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken)
        return usernamePasswordAuthentication
    }

    private fun getAuthenticatedClientElseThrowInvalidClient(authentication: Authentication): OAuth2ClientAuthenticationToken {
        var clientPrincipal: OAuth2ClientAuthenticationToken? = null

        if (authentication.principal is OAuth2ClientAuthenticationToken) {
            clientPrincipal = authentication.principal as OAuth2ClientAuthenticationToken
        }

        if (clientPrincipal != null && clientPrincipal.isAuthenticated) {
            return clientPrincipal
        }

        throw OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT)
    }


}