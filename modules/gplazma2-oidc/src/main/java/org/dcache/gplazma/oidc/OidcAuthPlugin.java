package org.dcache.gplazma.oidc;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.net.InternetDomainName;
import org.codehaus.jackson.JsonNode;
import org.dcache.auth.BearerTokenCredential;
import org.dcache.auth.EmailAddressPrincipal;
import org.dcache.auth.ExternalNamesPrincipal;
import org.dcache.auth.OidcSubjectPrincipal;
import org.dcache.gplazma.AuthenticationException;
import org.dcache.gplazma.oidc.helpers.AuthResult;
import org.dcache.gplazma.oidc.helpers.HttpJsonHelper;
import org.dcache.gplazma.plugins.GPlazmaAuthenticationPlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.Principal;
import java.util.Arrays;
import java.util.Properties;
import java.util.Random;
import java.util.Set;
import java.util.Map;
import java.util.HashSet;
import java.util.Base64;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import static com.google.common.base.Preconditions.checkArgument;
import static org.dcache.gplazma.util.Preconditions.checkAuthentication;

public class OidcAuthPlugin implements GPlazmaAuthenticationPlugin
{
    private final static Logger LOG = LoggerFactory.getLogger(OidcAuthPlugin.class);
    private final static String OIDC_HOSTNAMES = "gplazma.oidc.hostnames";

    private final LoadingCache<String, JsonNode> cache;
    private Set<String> discoveryDocs;
    private HttpJsonHelper httpJsonHelper;
    private final Random random = new Random();

    public OidcAuthPlugin(Properties properties)
    {
        this(properties, new HttpJsonHelper());
    }

    @VisibleForTesting
    OidcAuthPlugin(Properties properties, HttpJsonHelper helper)
    {
        this(properties,
             helper,
             CacheBuilder.newBuilder()
                .maximumSize(100)
                .expireAfterAccess(1, TimeUnit.HOURS)
                .build(
                    new CacheLoader<String, JsonNode>() {
                        @Override
                        public JsonNode load(String hostname) throws Exception {
                            JsonNode discoveryDoc = helper.doGet("https://" +
                                                    hostname +
                                                    "/.well-known/openid-configuration");
                            if ( discoveryDoc != null && discoveryDoc.has("userinfo_endpoint")) {
                                return discoveryDoc;
                            } else {
                                LOG.warn("Discovery Document from {} does not contain userinfo endpoint url {}",
                                        hostname, discoveryDoc);
                                return null;
                            }
                        }
                    }
                )
        );
    }

    @VisibleForTesting
    OidcAuthPlugin(Properties properties, HttpJsonHelper helper, LoadingCache<String, JsonNode> cache)
    {
        String oidcHostnamesProperty = properties.getProperty(OIDC_HOSTNAMES);

        checkArgument(oidcHostnamesProperty.length() > 0, "Oidc Hostnames not defined " + oidcHostnamesProperty);

        Set<String> oidcHostNames = Arrays.stream(oidcHostnamesProperty.split("\\s+"))
                                          .filter(not(String::isEmpty))
                                          .collect(Collectors.toSet());

        Map<Boolean, Set<String>> validHosts = oidcHostNames.parallelStream()
                                                            .collect(
                                                                    Collectors.groupingBy(InternetDomainName::isValid,
                                                                            Collectors.toSet())
                                                            );

        if (validHosts.containsKey(Boolean.FALSE)) {
            throw new IllegalArgumentException("Invalid Oidc Hostnames provided: " +
                    validHosts.get(Boolean.FALSE).toString());
        }
        checkArgument(validHosts.containsKey(Boolean.TRUE), "No Valid Oidc Hostnames: %s", oidcHostnamesProperty);

        this.discoveryDocs = validHosts.get(Boolean.TRUE);
        this.httpJsonHelper = helper;
        this.cache = cache;
    }

    @Override
    public void authenticate(Set<Object> publicCredentials,
                             Set<Object> privateCredentials,
                             Set<Principal> identifiedPrincipals)
            throws AuthenticationException
    {
        Set<BearerTokenCredential> bearerTokens = privateCredentials.parallelStream()
                                                              .filter(BearerTokenCredential.class::isInstance)
                                                              .map(BearerTokenCredential.class::cast)
                                                              .collect(Collectors.toSet());

        checkAuthentication(!bearerTokens.isEmpty(), "No bearer token in the credentials");

        Set<AuthResult> failures = new HashSet<>();
        for (BearerTokenCredential token : bearerTokens) {
            Set<AuthResult> resultSet = fetchUserPrincipals(token);
            if (!resultSet.isEmpty()) {
                if (resultSet.size() == 1 && resultSet.iterator().next().isSuccess()) {
                    identifiedPrincipals.addAll(resultSet.iterator().next().getPrincipals());
                    return;
                } else {
                    failures.addAll(resultSet);
                }
            }
        }

        String randomId = randomId();
        LOG.warn("OpenID Validation with hosts {}: {}", randomId, buildErrorMessage(failures));
        checkAuthentication(failures.isEmpty(), "OpenID Validation Failure : " + randomId);
    }

    Set<AuthResult> fetchUserPrincipals(BearerTokenCredential credential)
    {
        Set<AuthResult> result = new HashSet<>();
        for (String host : discoveryDocs) {
            try {
                JsonNode discoveryJson = cache.get(host);
                if (discoveryJson != null) {
                    String userInfoEndPoint = extractUserInfoEndPoint(discoveryJson);
                    if (userInfoEndPoint != null) {
                        AuthResult authResult = validateBearerTokenWithOpenIdProvider(credential,
                                                                                      userInfoEndPoint,
                                                                                      host);
                        if (authResult.isError()) {
                            result.add(authResult);
                        } else {
                            result.clear();
                            result.add(authResult);
                            return result;
                        }
                    }
                }
            } catch (ExecutionException e) {
                result.add(AuthResult.createAuthError(host, e.getMessage()));
            }
        }
        return result;
    }

    private AuthResult validateBearerTokenWithOpenIdProvider
            (BearerTokenCredential credential, String infoUrl, String host)
    {
        try {
            JsonNode userInfo = getUserInfo(infoUrl, credential.getToken());
            if (userInfo != null && userInfo.has("sub")) {
                Set<Principal> principals = new HashSet<>();
                LOG.trace("User Info As Obtained from OpenIDC {}", userInfo);
                try {
                    addSub(userInfo, principals);
                    addNames(userInfo, principals);
                    addEmail(userInfo, principals);
                    return AuthResult.createAuthSuccess(host, principals);
                } catch (IllegalArgumentException iae) {
                    return AuthResult.createAuthError(host, "Problem parsing User Info : " + iae.getMessage());
                }
            } else {
                return AuthResult.createAuthError(host, "No Opend ID Subject in User Info");
            }
        } catch (AuthenticationException e) {
            return AuthResult.createAuthError(host, e.getMessage());
        } catch (IOException e) {
            return AuthResult.createAuthError(host, "Http Get Error on fetching User Info" + e.getMessage());
        }
    }

    private JsonNode getUserInfo(String url, String token) throws AuthenticationException, IOException
    {
        JsonNode userInfo = httpJsonHelper.doGetWithToken(url, token);
        if (userInfo.has("error")) {
            String error = userInfo.get("error").asText();
            String errorDescription = userInfo.get("error_description").asText();
            throw new AuthenticationException("OpenID Connect error : [" + error + ", " + errorDescription + " ]");
        } else {
            return userInfo;
        }
    }

    private String extractUserInfoEndPoint(JsonNode discoveryDoc)
    {
        if (discoveryDoc.has("userinfo_endpoint")) {
            return discoveryDoc.get("userinfo_endpoint").asText();
        } else {
            return null;
        }
    }

    private void addEmail(JsonNode userInfo, Set<Principal> principals)
    {
        if (userInfo.has("email")) {
            principals.add(new EmailAddressPrincipal(userInfo.get("email").asText()));
        }
    }

    private void addNames(JsonNode userInfo, Set<Principal> principals)
    {
        JsonNode givenName = userInfo.get("given_name");
        JsonNode familyName = userInfo.get("family_name");
        JsonNode name = userInfo.get("name");
        if (givenName != null || familyName != null || name != null) {
            principals.add(new ExternalNamesPrincipal(
                    givenName == null ? null : givenName.asText(),
                    familyName == null ? null : familyName.asText(),
                    name == null ? null : name.asText()));
        }
    }

    private boolean addSub(JsonNode userInfo, Set<Principal> principals)
    {
        return principals.add(new OidcSubjectPrincipal(userInfo.get("sub").asText()));
    }

    private static <T> Predicate<T> not(Predicate<T> t) {
        return t.negate();
    }

    private String buildErrorMessage(Set<AuthResult> errors)
    {
        return errors.isEmpty() ? "(unknown)" : errors.stream().
                map(AuthResult::toString).
                collect(Collectors.joining(", ", "[", "]"));
    }

    private String randomId() {
        byte[] rawId = new byte[3]; // a Base64 char represents 6 bits; 4 chars represent 3 bytes.
        random.nextBytes(rawId);
        return Base64.getEncoder().withoutPadding().encodeToString(rawId);
    }
}
