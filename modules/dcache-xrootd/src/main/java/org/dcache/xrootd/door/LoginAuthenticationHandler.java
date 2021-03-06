package org.dcache.xrootd.door;

import io.netty.channel.ChannelHandlerContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import diskCacheV111.util.CacheException;
import diskCacheV111.util.PermissionDeniedCacheException;

import org.dcache.auth.LoginReply;
import org.dcache.auth.LoginStrategy;
import org.dcache.auth.Origin;
import org.dcache.auth.Subjects;
import org.dcache.util.CertificateFactories;
import org.dcache.xrootd.core.XrootdAuthenticationHandler;
import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.plugins.AuthenticationFactory;
import org.dcache.xrootd.plugins.ProxyDelegationClient;

import static java.util.Arrays.asList;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_NotAuthorized;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ServerError;

/**
 * An XrootdAuthenticationHandler which after successful
 * authentication delegates login to a LoginStrategy.
 *
 * Generates a LoginEvent after successful login.
 */
public class LoginAuthenticationHandler
    extends XrootdAuthenticationHandler
{
    private static final Logger _log =
        LoggerFactory.getLogger(LoginAuthenticationHandler.class);

    private LoginStrategy _loginStrategy;
    private CertificateFactory _cf;

    public LoginAuthenticationHandler(AuthenticationFactory authenticationFactory,
                                      ProxyDelegationClient proxyDelegationClient,
                                      LoginStrategy loginStrategy)
    {
        super(authenticationFactory, proxyDelegationClient);
        _loginStrategy = loginStrategy;
        _cf = CertificateFactories.newX509CertificateFactory();
    }

    @Override
    protected Subject login(ChannelHandlerContext context, Subject subject)
        throws XrootdException
    {
        try {
            subject = addOrigin(subject, ((InetSocketAddress) context.channel().remoteAddress()).getAddress());
            LoginReply reply = _loginStrategy.login(translateSubject(subject));
            context.fireUserEventTriggered(new LoginEvent(reply));
            return reply.getSubject();
        } catch (PermissionDeniedCacheException e) {
            _log.warn("Authorization denied for {}: {}",
                    Subjects.toString(subject), e.getMessage());
            throw new XrootdException(kXR_NotAuthorized, e.getMessage());
        } catch (CacheException | CertificateException e) {
            _log.error("Authorization failed for {}: {}",
                       Subjects.toString(subject), e.getMessage());
            throw new XrootdException(kXR_ServerError, e.getMessage());
        }
    }

    private Subject addOrigin(Subject subject, InetAddress address)
    {
        Subject newSubject;
        if (subject == null) {
            newSubject = new Subject();
        } else {
            newSubject = new Subject(false,
                                      subject.getPrincipals(),
                                      subject.getPublicCredentials(),
                                      subject.getPrivateCredentials());
        }
        newSubject.getPrincipals().add(new Origin(address));
        return newSubject;
    }

    private Subject translateSubject(Subject subject) throws CertificateException
    {
        if (subject == null) {
            return null;
        }
        Set<Object> publicCredentials = new HashSet<>();
        for (Object credential : subject.getPublicCredentials()) {
            if (credential instanceof X509Certificate[]) {
                publicCredentials.add(_cf.generateCertPath(asList((X509Certificate[]) credential)));
            } else {
                publicCredentials.add(credential);
            }
        }
        return new Subject(false, subject.getPrincipals(), publicCredentials, subject.getPrivateCredentials());
    }
}
