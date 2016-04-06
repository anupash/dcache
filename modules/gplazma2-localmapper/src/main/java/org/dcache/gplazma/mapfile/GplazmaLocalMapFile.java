package org.dcache.gplazma.mapfile;

import org.dcache.auth.EmailAddressPrincipal;
import org.dcache.auth.OidcSubjectPrincipal;
import org.dcache.auth.UserNamePrincipal;
import org.dcache.gplazma.mapfile.exception.GplazmaParseMapFileException;
import org.globus.gsi.gssapi.jaas.GlobusPrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.kerberos.KerberosPrincipal;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.Principal;
import java.util.*;

public class GplazmaLocalMapFile
{
    private static final Logger LOG = LoggerFactory.getLogger(GplazmaLocalMapFile.class);

    private File file;
    private long lastLoaded;
    private Map<Principal,Set<Principal>> map;
    private static final String[] principalTypes = new String[]{"dn", "email", "username", "kerberos", "oidc" };

    public GplazmaLocalMapFile(String path)
    {
        this(new File(path));
    }

    public GplazmaLocalMapFile(File file)
    {
        this.file = file;
    }

    public synchronized void refresh()
    {
        try {
            long now = System.currentTimeMillis();
            if (!file.canRead()) {
                LOG.warn("Could not read local-map file. Will use cached copy.");
            } else if (lastLoaded < file.lastModified()) {
                LOG.trace("Gplazma2 LocalMapper Handler reading file {}", file);
                BufferedReader reader = new BufferedReader(new FileReader(file));
                map = parseMapFile(reader);
                lastLoaded = now;
            }
        } catch (IOException e) {
            LOG.error("Failed to load local-mapper configuration: " + e.getMessage());
        }
    }


    private static Map<Principal,Set<Principal>> parseMapFile(BufferedReader reader) throws IOException
    {
        Map<Principal,Set<Principal>> map = new HashMap<>();
        String line;
        String lineOrig;
        int lineCount = 0;
        while ((line = reader.readLine()) != null) {
            lineOrig = line = line.trim();
            lineCount++;
            if (line.isEmpty() || line.charAt(0) == '#') continue;

            try {
                String firstPredicate = line.split(":", 2)[0];
                Principal key = toPrincipal(line, firstPredicate);

                Set<Principal> mappings = new LinkedHashSet<>();
                line = line.substring(line.indexOf(':') + 1);

                for (String predicate: principalTypes ){
                    fetchAllPrincipalsofPredicate(line, predicate, mappings);
                }

                if (!mappings.isEmpty()) {
                    map.putIfAbsent(key, mappings);
                } else {
                    LOG.warn("Line[{}]: ({}) has an empty mapping", lineCount, lineOrig);
                }
            } catch (GplazmaParseMapFileException e) {
                LOG.warn("Line[{}]: ({}), {}", lineCount, lineOrig, e.getMessage());
            }
        }
        return map;
    }

    private static void fetchAllPrincipalsofPredicate(String line, String predicate, Set<Principal> principals)
            throws GplazmaParseMapFileException
    {
        int index = line.indexOf(predicate + ":");
        while (index != -1) {
            principals.add(toPrincipal(line, predicate, index));
            index = line.substring(index+1).indexOf(predicate);
        }
    }

    private static Principal toPrincipal(String line, String predicate) throws GplazmaParseMapFileException
    {
        int index = line.indexOf(predicate);
        if (index != -1) {
            return toPrincipal(line, predicate, index);
        } else {
            throw new GplazmaParseMapFileException("Invalid predicate");
        }
    }

    private static Principal toPrincipal(String line, String predicate, int index) throws GplazmaParseMapFileException
    {
        String principal = getRawPrincipal(line, index, predicate);
        if (principal != null) {
            try {
                return createPrincipal(predicate, principal);
            } catch (GplazmaParseMapFileException e) {
                throw e;
            } catch (Exception e) {
                throw new GplazmaParseMapFileException(
                        "Problem parsing local map file with predicate: " + predicate +
                        ", principal: " + principal);
            }
        } else {
            throw new GplazmaParseMapFileException("Invalid Predicate");
        }
    }

    private static Principal createPrincipal(String predicate, String principal) throws GplazmaParseMapFileException {
        switch (predicate) {
            case "oidc":
                return new OidcSubjectPrincipal(principal);
            case "email":
                return new EmailAddressPrincipal(principal);
            case "username":
                return new UserNamePrincipal(principal);
            case "dn":
                return new GlobusPrincipal(principal);
            case "kerberos":
                return new KerberosPrincipal(principal);
            default:
                throw new GplazmaParseMapFileException("Not supported predicate " + predicate);
        }
    }

    private static String getRawPrincipal(String line, int index, String predicate)
            throws GplazmaParseMapFileException
    {
        String principal;
        int firstQuote = index + predicate.length() + 1;
        if (line.charAt(firstQuote) == '\"') {
            int secondQuote = line.indexOf('\"', firstQuote + 1);
            if (secondQuote == -1) {
                throw new GplazmaParseMapFileException("Problem parsing local map file with entry [" + line + "]");
            } else {
                principal = line.substring(firstQuote + 1, secondQuote);
            }
        } else {
            String[] principals = line.substring(firstQuote).split("\\s+", 2);
            if (!predicate.equals("dn") ||
                (predicate.equals("dn") &&
                    (principals[1].startsWith("email") || principals[1].startsWith("username") ||
                     principals[1].startsWith("oidc") || principals[1].startsWith("kerberos")))
                ) {
                principal = principals[0];
            } else {
                throw new GplazmaParseMapFileException("DN must be enclosed in quotes, if it has spaces");
            }
        }
        return principal;
    }

    public Set<Principal> getMappedPrincipals(Principal principal)
    {
        return map.containsKey(principal) ? map.get(principal):new HashSet<>();
    }
}
