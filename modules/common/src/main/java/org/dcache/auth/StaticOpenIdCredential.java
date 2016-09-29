package org.dcache.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.Objects;

public class StaticOpenIdCredential implements OpenIdCredential, Serializable
{
    private static final long serialVersionUID = 1L;
    private static final Logger LOG =
            LoggerFactory.getLogger(StaticOpenIdCredential.class);

    private String accessToken;
    private long expiresAt;
    private final String issuedTokenType;
    private final String refreshToken;
    private final String scope;
    private final String tokenType;

    // Use to refresh Access Token
    private final OpenIdClientSecret clientCredential;
    private final String openidProvider;

    private StaticOpenIdCredential(OidCredentialBuilder builder) {
        this.accessToken = builder._accessToken;
        this.expiresAt = System.currentTimeMillis() + (builder._expiresIn - 60)*1000L;
        this.issuedTokenType = builder._issuedTokenType;
        this.refreshToken = builder._refreshToken;
        this.scope = builder._scope;
        this.tokenType = builder._tokenType;
        this.clientCredential = builder._clientCredential;
        this.openidProvider = builder._urlOpenidProvider;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public void setExpiresAt(long expiresAt) {
        this.expiresAt = expiresAt;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public long getExpiresAt() {
        return expiresAt;
    }

    public String getIssuedTokenType() {
        return issuedTokenType;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public String getScope() {
        return scope;
    }

    public String getTokenType() {
        return tokenType;
    }

    public OpenIdClientSecret getClientCredential() {
        return clientCredential;
    }

    public String getOpenidProvider() {
        return openidProvider;
    }

    @Override
    public String getBearerToken() {
        return getAccessToken();
    }

    public boolean timeToRefresh() {
        if(this.expiresAt > System.currentTimeMillis()) {
            return false;
        } else {
            return true;
        }
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
            return true;
        if (!(o instanceof StaticOpenIdCredential))
            return false;

        StaticOpenIdCredential that = (StaticOpenIdCredential) o;

        if (expiresAt != that.expiresAt)
            return false;
        if (!accessToken.equals(that.accessToken))
            return false;
        if (!issuedTokenType.equals(that.issuedTokenType))
            return false;
        if (!refreshToken.equals(that.refreshToken))
            return false;
        if (!scope.equals(that.scope))
            return false;
        if (!tokenType.equals(that.tokenType))
            return false;
        if (!clientCredential.equals(that.clientCredential))
            return false;
        return openidProvider.equals(that.openidProvider);
    }

    @Override
    public int hashCode()
    {
        return Objects.hash(accessToken,
                            expiresAt,
                            issuedTokenType,
                            refreshToken,
                            scope,
                            tokenType,
                            clientCredential, openidProvider);
    }

    public static class OidCredentialBuilder
    {
        private String _accessToken = null;
        private long _expiresIn = 0L;
        private String _issuedTokenType = null;
        private String _refreshToken = null;
        private String _scope = null;
        private String _tokenType = null;
        private OpenIdClientSecret _clientCredential = null;
        private String _urlOpenidProvider = null;

        public OidCredentialBuilder(String accessToken)
        {
            _accessToken = accessToken;
        }

        public OidCredentialBuilder expiry(long expiresIn)
        {
            this._expiresIn = expiresIn;
            return this;
        }

        public OidCredentialBuilder refreshToken(String refreshToken)
        {
            this._refreshToken = refreshToken;
            return this;
        }

        public OidCredentialBuilder issuedTokenType(String issuedTokenType)
        {
            this._issuedTokenType = issuedTokenType;
            return this;
        }

        public OidCredentialBuilder scope(String scope)
        {
            this._scope = scope;
            return this;
        }

        public OidCredentialBuilder tokenType(String tokenType)
        {
            this._tokenType = tokenType;
            return this;
        }

        public OidCredentialBuilder clientCredential(OpenIdClientSecret clientCredential)
        {
            this._clientCredential = clientCredential;
            return this;
        }

        public OidCredentialBuilder provider(String url)
        {
            this._urlOpenidProvider = url;
            return this;
        }

        public StaticOpenIdCredential build()
        {
            return new StaticOpenIdCredential(this);
        }
    }
}
