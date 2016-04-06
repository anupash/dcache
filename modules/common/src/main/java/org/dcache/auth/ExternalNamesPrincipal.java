package org.dcache.auth;

import com.google.common.base.Joiner;

import java.io.Serializable;
import java.security.Principal;

import static com.google.common.base.Preconditions.checkArgument;

public class ExternalNamesPrincipal implements Principal, Serializable
{
    private static final long serialVersionUID = 1L;
    private final String _givenName;
    private final String _familyName;
    private final String _fullName;

    public ExternalNamesPrincipal(String givenName, String familyName, String fullName)
    {
        checkArgument( givenName != null || familyName != null || fullName != null, "No Names given");
        _givenName = givenName;
        _familyName = familyName;
        if (fullName == null) {
            _fullName = Joiner.on(' ').skipNulls().join(givenName, familyName);
        } else {
            _fullName = fullName;
        }
    }

    @Override
    public String getName()
    {
        return _fullName;
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o) {
            return true;
        }
        if (!(o instanceof ExternalNamesPrincipal)) {
            return false;
        }

        ExternalNamesPrincipal that = (ExternalNamesPrincipal) o;
        if (!_givenName.equals(that._givenName)) {
            return false;
        }
        if (!_familyName.equals(that._familyName)) {
            return false;
        }
        return _fullName.equals(that._fullName);

    }

    @Override
    public int hashCode() {
        int result = _givenName != null ? _givenName.hashCode() : 0;
        result = 31 * result + (_familyName != null ? _familyName.hashCode() : 0);
        result = 31 * result + _fullName.hashCode();
        return result;
    }

    @Override
    public String toString() {
        return "ExternalNamesPrincipal{" +
                ", _fullName='" + _fullName + '\'' +
                '}';
    }
}
