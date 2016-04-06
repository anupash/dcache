package org.dcache.gplazma.oidc.helpers;


import java.security.Principal;
import java.util.Set;

public class AuthResult
{
    private final String result;
    private final String host;
    private final Set<Principal> principals;

    public AuthResult(String result, String host, Set<Principal> principals)
    {
        this.result = result;
        this.host = host;
        this.principals = principals;
    }

    public static AuthResult createAuthError(String host, String result)
    {
        return new AuthResult(result, host, null);
    }

    public static AuthResult createAuthSuccess(String host, Set<Principal> principals)
    {
        return new AuthResult(null, host, principals);
    }

    public boolean isError()
    {
        return principals == null && !result.isEmpty();
    }

    public boolean isSuccess()
    {
        return !isError();
    }

    public Set<Principal> getPrincipals()
    {
        return principals;
    }

    @Override
    public String toString() {
        return "(\"" + host + "\", " + result + ")";
    }
}
