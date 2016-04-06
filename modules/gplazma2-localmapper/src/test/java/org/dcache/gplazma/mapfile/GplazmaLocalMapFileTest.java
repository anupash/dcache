package org.dcache.gplazma.mapfile;

import org.dcache.auth.EmailAddressPrincipal;
import org.dcache.auth.OidcSubjectPrincipal;
import org.dcache.auth.UserNamePrincipal;
import org.globus.gsi.gssapi.jaas.GlobusPrincipal;
import org.hamcrest.Matcher;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import javax.security.auth.kerberos.KerberosPrincipal;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.Principal;
import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;


public class GplazmaLocalMapFileTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    private GplazmaLocalMapFile mapFile;
    private Set<Principal> principals;
    private File config;

    @After
    public void tearDown() throws Exception
    {
        config.delete();
        config = null;
    }

    @Test
    public void shouldFailWhenWrongMapFormatDN() throws Exception {
        givenConfig("dn:kermit@dcache.org    username:kermit");

        whenMapUsername(withDN("dn:\"/C=DE/S=Hamburg/OU=desy.de/CN=Kermit The Frog\""));

        assertThat(principals, is(empty()));
    }

    @Test
    public void shouldFailWhenWrongMapFormatDN1() throws Exception {
        givenConfig("dn:/C=DE/S=Hamburg/OU=desy.de/CN=Kermit The Frog    username:kermit");

        whenMapUsername(withDN("dn:\"/C=DE/S=Hamburg/OU=desy.de/CN=Kermit The Frog\""));

        assertThat(principals, is(empty()));
    }

    @Test
    public void shouldFailWhenWrongMapFormatKerberos() throws Exception {
        givenConfig("krb:kermit@DESY.DE    username:kermit");

        whenMapUsername(withKerberos("kermit@DESY.DE"));

        assertThat(principals, is(empty()));
    }

    @Test
    public void shouldFailWhenWrongMapFormatOidc() throws Exception {
        givenConfig("oid:googleopenidsubject    username:kermit");

        whenMapUsername(withOidcSubject("googleopenidsubject"));

        assertThat(principals, is(empty()));
    }

    @Test
    public void shouldFailWhenWrongMapFormatEmail() throws Exception {
        givenConfig("mail:kermit@dcache.org    username:kermit");

        whenMapUsername(withEmail("kermit@dcache.org"));

        assertThat(principals, is(empty()));
    }

    @Test
    public void shouldFailWhenWrongMapFormatEmail2() throws Exception {
        givenConfig("email:kermit.dcache.org    username:kermit");

        whenMapUsername(withEmail("kermit@dcache.org"));

        assertThat(principals, is(empty()));
    }

    @Test
    public void shouldPassWhenEmailMapped() throws Exception {
        givenConfig("email:kermit@dcache.org    username:kermit");

        whenMapUsername(withEmail("kermit@dcache.org"));

        assertThat(principals, is(not(empty())));
        assertThat(principals, hasUserNamePrincipal("kermit"));
    }

    @Test
    public void shouldPassWhenEmailMapped1() throws Exception {
        givenConfig("email:\"kermit@dcache.org\"    username:kermit");

        whenMapUsername(withEmail("kermit@dcache.org"));

        assertThat(principals, is(not(empty())));
        assertThat(principals, hasUserNamePrincipal("kermit"));
    }

    @Test
    public void shouldPassWhenEmailMapped2() throws Exception {
        givenConfig("email:\"kermit@dcache.org\"    username:\"kermit\"");

        whenMapUsername(withEmail("kermit@dcache.org"));

        assertThat(principals, is(not(empty())));
        assertThat(principals, hasUserNamePrincipal("kermit"));
    }

    @Test
    public void shouldPassWhenDNMapped() throws Exception {
        givenConfig("dn:\"/C=DE/O=Hamburg/OU=desy.de/CN=Kermit The Frog\"    username:kermit");

        whenMapUsername(withDN("/C=DE/O=Hamburg/OU=desy.de/CN=Kermit The Frog"));

        assertThat(principals, is(not(empty())));
        assertThat(principals, hasUserNamePrincipal("kermit"));
    }

    @Test
    public void shouldPassWhenOidcMapped() throws Exception {
        givenConfig("oidc:googleoidcsubject    username:kermit");

        whenMapUsername(withOidcSubject("googleoidcsubject"));

        assertThat(principals, is(not(empty())));
        assertThat(principals, hasUserNamePrincipal("kermit"));
    }

    @Test
    public void testRefresh() throws Exception {
        givenConfig("  \n");

        whenMapUsername(withEmail("kermit@dcache.org"));
        assertThat(principals, is(empty()));

        appendConfig("email:kermit@dcache.org    username:kermit\n");

        whenMapUsername(withEmail("kermit@dcache.org"));
        assertThat(principals, is(empty()));

        mapFile.refresh();

        whenMapUsername(withEmail("kermit@dcache.org"));
        assertThat(principals, is(not(empty())));
        assertThat(principals, hasUserNamePrincipal("kermit"));
    }

    /*----------------------- Helpers -----------------------------*/

    private void givenConfig(String mapping) throws IOException {
        config = tempFolder.newFile("localmapper.conf");
        Files.write(config.toPath(), mapping.getBytes(), StandardOpenOption.APPEND);
        mapFile = new GplazmaLocalMapFile(config);
        mapFile.refresh();
    }

    private void appendConfig(String mapping) throws InterruptedException, IOException {
        Files.write(config.toPath(), mapping.getBytes(), StandardOpenOption.APPEND);
        // Add 1 sec to modified time because not all platforms
        // support file-modification times to the milli-second
        config.setLastModified(System.currentTimeMillis()+1000);
    }

    private void whenMapUsername(Principal principal) {
        principals = mapFile.getMappedPrincipals(principal);
    }

    private Principal withDN(String s) {
        return new GlobusPrincipal(s);
    }

    private Principal withKerberos(String s) {
        return new KerberosPrincipal(s);
    }

    private Principal withEmail(String s) {
        return new EmailAddressPrincipal(s);
    }

    private Principal withOidcSubject(String s) {
        return new OidcSubjectPrincipal(s);
    }

    private Matcher<Iterable<? super UserNamePrincipal>> hasUserNamePrincipal(String username) {
        return hasItem(new UserNamePrincipal(username));
    }


}