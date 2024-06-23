package org.springframework.security.oauth2.server.authorization.authentication

import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.AuthorizationGrantType

class OAuth2ResourceOwnerPasswordAuthenticationToken(
    val username: String,
    val password: String,
    private val clientPrincipal: Authentication,
    val scopes: Set<String>,
    private val additionalParams: Map<String, Any>
) : OAuth2AuthorizationGrantAuthenticationToken(AuthorizationGrantType.PASSWORD, clientPrincipal, additionalParams)