package org.dcache.auth;

import com.google.common.base.Charsets;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.BasicHttpContext;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

public class OpenIdCredentialDecorator implements OpenIdCredential
{
    private final StaticOpenIdCredential credential;
    private final HttpClient client;
    private static final Logger LOG = LoggerFactory.getLogger(OpenIdCredentialDecorator.class);

    public OpenIdCredentialDecorator(OpenIdCredential credential, HttpClient client)
    {
        checkArgument(credential instanceof StaticOpenIdCredential, "Credential not of type StaticOpenIdCredential");
        this.client = checkNotNull(client, "Http Client can't be null");
        this.credential = (StaticOpenIdCredential)credential;
    }

    public OpenIdCredentialDecorator(OpenIdCredential credential)
    {
        checkArgument(credential instanceof StaticOpenIdCredential, "Credential not of type StaticOpenIdCredential");
        this.client = HttpClientBuilder.create().build();
        this.credential = (StaticOpenIdCredential)credential;
    }

    @Override
    public String getBearerToken()
    {
        if (credential.timeToRefresh()) {
            refreshOpenIdCredentials();
        }
        return credential.getBearerToken();
    }

    private synchronized void refreshOpenIdCredentials() {
        HttpPost post = new HttpPost(credential.getOpenidProvider());
        BasicScheme scheme = new BasicScheme(Charsets.UTF_8);
        UsernamePasswordCredentials clientCreds = new UsernamePasswordCredentials(
                credential.getClientCredential().getId(),
                credential.getClientCredential().getSecret());

        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("client_id", credential.getClientCredential().getId()));
        params.add(new BasicNameValuePair("client_secret", credential.getClientCredential().getSecret()));
        params.add(new BasicNameValuePair("grant_type", "refresh_token"));
        params.add(new BasicNameValuePair("refresh_token", credential.getRefreshToken()));
        params.add(new BasicNameValuePair("scope", credential.getScope()));
        try {
            post.setEntity(new UrlEncodedFormEntity(params));
            post.addHeader(scheme.authenticate(clientCreds, post, new BasicHttpContext()) );

            HttpResponse response = client.execute(post);
            if (response.getStatusLine().getStatusCode() == 200) {
                updateCredential(parseResponseToJson(response));
            }
        } catch (IOException | AuthenticationException e) {
            e.printStackTrace();
        }
    }

    private JSONObject parseResponseToJson(HttpResponse response) throws IOException
    {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        response.getEntity().writeTo(os);
        return new JSONObject(new String(os.toByteArray(), Charsets.UTF_8));
    }

    private void updateCredential(JSONObject json)
    {
        credential.setAccessToken(json.getString("access_token"));
        credential.setExpiresAt(System.currentTimeMillis() + (json.getLong("expires_in") - 60)*1000L);
    }
}
