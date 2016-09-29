package org.dcache.auth;

public interface OpenIdCredential
{
    public String getBearerToken();

    public String getAccessToken();

    public long getExpiresAt();

    public String getIssuedTokenType();

    public String getRefreshToken();

    public String getScope();

    public String getTokenType();

    public OpenIdClientSecret getClientCredential();

    public String getOpenidProvider();
}
