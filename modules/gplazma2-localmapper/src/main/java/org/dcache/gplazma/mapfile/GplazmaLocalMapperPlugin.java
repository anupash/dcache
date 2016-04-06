package org.dcache.gplazma.mapfile;

import org.dcache.auth.EmailAddressPrincipal;
import org.dcache.auth.LoginNamePrincipal;
import org.dcache.auth.OidcSubjectPrincipal;
import org.dcache.auth.UserNamePrincipal;
import org.dcache.gplazma.AuthenticationException;
import org.dcache.gplazma.plugins.GPlazmaMappingPlugin;
import org.globus.gsi.gssapi.jaas.GlobusPrincipal;

import javax.security.auth.kerberos.KerberosPrincipal;
import java.security.Principal;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Predicates.instanceOf;
import static com.google.common.collect.Iterables.*;
import static org.dcache.gplazma.util.Preconditions.checkAuthentication;

public class GplazmaLocalMapperPlugin implements GPlazmaMappingPlugin
{

    private GplazmaLocalMapFile principalMaps;
    private static final String GPLAZMA2_MAP_FILE = "gplazma.localmapper.file";

    public GplazmaLocalMapperPlugin(Properties properties)
    {
        String path = properties.getProperty(GPLAZMA2_MAP_FILE);
        checkArgument(path != null && !path.isEmpty(), "Undefined property: " + GPLAZMA2_MAP_FILE);
        principalMaps = new GplazmaLocalMapFile(path);
    }

    public GplazmaLocalMapperPlugin(GplazmaLocalMapFile mapFile)
    {
        principalMaps = checkNotNull(mapFile, "Local mapping file can't be null");
    }

    public void map(Set<Principal> principals) throws AuthenticationException
    {
        if (any(principals, instanceOf(UserNamePrincipal.class))) {
            return;
        } else {
            principalMaps.refresh();
            Set<Principal> p = getMappingFor(principals);
            checkAuthentication(p != null, "no mapping");
            principals.addAll(p);
        }
    }

    private Set<Principal> getMappingFor(Set<Principal> principals)
            throws AuthenticationException
    {
        Principal loginName =
                find(principals, instanceOf(LoginNamePrincipal.class), null);
        Set<Set<Principal>> all = new HashSet<>();
        for (Principal principal: principals) {
            if (principal instanceof GlobusPrincipal ||
                principal instanceof KerberosPrincipal ||
                principal instanceof OidcSubjectPrincipal ||
                principal instanceof EmailAddressPrincipal) {

                Set<Principal> mappedprincipals = principalMaps.getMappedPrincipals(principal);
                if (!mappedprincipals.isEmpty()) {
                    mappedprincipals = mappedprincipals.stream()
                            .filter(p -> (p instanceof UserNamePrincipal))
                            .collect(Collectors.toSet());
                    all.add(mappedprincipals);
                }
            }
        }

        if (!all.isEmpty()) {
            if (loginName != null) {
                for (Set<Principal> one: all) {
                    if (one.contains(new UserNamePrincipal(loginName.getName()))) {
                        return one;
                    }
                }
            }
            return get(all, 0);
        }
        throw new AuthenticationException();
    }
}
