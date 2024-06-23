package org.springframework.security.oauth2.server.authorization.authentication

import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.web.authentication.AuthenticationConverter
import org.springframework.util.StringUtils


class OAuth2ResourceOwnerPasswordAuthenticationConverter : AuthenticationConverter {

    companion object {
        private const val ACCESS_TOKEN_REQUEST_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2"
    }

    override fun convert(request: HttpServletRequest): Authentication? {
        // grant_type (REQUIRED)
        val grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE)

        if (AuthorizationGrantType.PASSWORD.value != grantType) {
            return null
        }

        val parameters = request.parameterMap

        // scope (OPTIONAL)
        val scope = parameters[OAuth2ParameterNames.SCOPE]?.first()
        if (StringUtils.hasText(scope) && parameters[OAuth2ParameterNames.SCOPE]?.size != 1) {
            throwOAuth2ParameterError(OAuth2ParameterNames.SCOPE)
        }
        val requestedScopes: Set<String> = scope?.split(" ")?.toSet() ?: emptySet()

        // username (REQUIRED)
        val username = parameters[OAuth2ParameterNames.USERNAME]?.first()
        if (!StringUtils.hasText(username) || parameters[OAuth2ParameterNames.USERNAME]?.size != 1) {
            throwOAuth2ParameterError(OAuth2ParameterNames.USERNAME)
        }

        // password (REQUIRED)
        val password = parameters[OAuth2ParameterNames.PASSWORD]?.first()
        if (!StringUtils.hasText(password) || parameters[OAuth2ParameterNames.PASSWORD]?.size != 1) {
            throwOAuth2ParameterError(OAuth2ParameterNames.PASSWORD)
        }

        val clientPrincipal = SecurityContextHolder.getContext().authentication

        val additionalParameters: Map<String, Any> = parameters
            .filterKeys {
                it !in setOf(
                    OAuth2ParameterNames.GRANT_TYPE,
                    OAuth2ParameterNames.SCOPE,
                    OAuth2ParameterNames.USERNAME,
                    OAuth2ParameterNames.PASSWORD
                )
            }
            .mapNotNull { (k, v) -> Pair(k, v[0]) }
            .toMap()

        return OAuth2ResourceOwnerPasswordAuthenticationToken(
            username!!,
            password!!,
            clientPrincipal,
            requestedScopes,
            additionalParameters
        )
    }

    private fun throwOAuth2ParameterError(parameterName: String) {
        val error = OAuth2Error(
            OAuth2ErrorCodes.INVALID_REQUEST,
            "OAuth2 parameter: $parameterName",
            ACCESS_TOKEN_REQUEST_ERROR_URI
        )
        throw OAuth2AuthenticationException(error)
    }
}