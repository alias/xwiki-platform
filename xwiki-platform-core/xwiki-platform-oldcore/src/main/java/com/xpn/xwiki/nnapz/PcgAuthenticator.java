package com.xpn.xwiki.nnapz;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.user.api.XWikiUser;
import com.xpn.xwiki.user.impl.xwiki.XWikiAuthServiceImpl;
import com.xpn.xwiki.user.impl.xwiki.XWikiAuthenticator;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.securityfilter.filter.SecurityRequestWrapper;
import org.securityfilter.realm.SimplePrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.model.reference.DocumentReference;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

/**
 * Authenticates calls from PCG that come along with a token and system parameter.
 * The token is forwarded to auth in oekobox-online.de's API. If that succeeds, the returned user information is used
 * to look up the local user. If she does not exist yet, we create it.
 *
 * If these parameters are not there, we forward to the standard auth class.
 *
 * Building:
 * * check out with long filenames enabled in git and in windows10
 * * use the settings.xml from
 * * 1) clean "XWIKI Platform - Legacy - Old Core"
 * * 2) rebuild "XWIKI Platform - Old Core"
 * * 3) build "XWIKI Platform - Legacy - Old Core"  (repacks somehow)
 * * 4) copy the resulting jar (xwiki-platform-legacy-oldcore-9.6.1-SNAPSHOT.jar)
 *         and override the installed xwiki-platform-legacy-oldcore-9.6.jar
 *
 * From studying http://platform.xwiki.org/xwiki/bin/view/AdminGuide/Authentication ff (and sandbox)
 *
 * @author Bob Schulze
 * @version $Id$
 * @since 9.6.x
 */
public class PcgAuthenticator extends XWikiAuthServiceImpl {

    private static final Logger LOGGER = LoggerFactory.getLogger(PcgAuthenticator.class);

    @Override
    public XWikiUser checkAuth(XWikiContext context) throws XWikiException {
        final HttpServletRequest req = context.getRequest().getHttpServletRequest();

        LOGGER.warn("*** CTX user: " + context.getUserReference());

        // are we in a regular form authentication or any other auth action that we better do not interfere?
        if (req.getParameter("j_username") != null || req.getParameter("srid") != null
                 || req.getPathInfo().toLowerCase().contains("logout")) {
            LOGGER.warn("auth activity, delegate to parent " + super.getClass());
            return super.checkAuth(context);
        }
        // try our token
        String token = req.getParameter("oo-token");
        SecurityRequestWrapper wrappedRequest = getSecurityRequestWrapper(context, req);
        if (token == null) {
            // check if we have one already
            Principal p = wrappedRequest.getUserPrincipal();
            if (p != null) {
                String fqName = p.getName();
                int inx = fqName.indexOf(":");
                if (inx > -1) {
                    String name = fqName.substring(inx+1);
                    LOGGER.warn("have already " + name);
                    return new XWikiUser(name.startsWith("XWiki.") ? name : "XWiki." + name);
                }
            }
            return super.checkAuth(context); // should forward to login
        }

        // some validation
        if (token.length() > 300) {
            LOGGER.error("Token has unusual size, abort");
            return null;
        }

        // lets try pcg auth
        LOGGER.warn("Getting PCG Auth for " + token + " Wiki " + context.getWikiId());
        String system = req.getParameter("oo-system");
        if (system == null || system.trim().length() == 0) {
            LOGGER.error("oo-system parameter missing. Ignore auth request.");
            return null;
        }

        // API call to oo
        JSONArray[] authenticatedUser;
        try {
            authenticatedUser = callOO(system, token);
        } catch (URISyntaxException e) {
            LOGGER.error("Wrong URL for " + system + ": " + e.getMessage());
            return null;
        } catch (IOException e) {
            LOGGER.error("Call failed for " + system + ": " + e.getMessage());
            return null;
        }
        if (authenticatedUser[0] == null || authenticatedUser[1] == null) {
            LOGGER.error("Call failed for " + system + ": no data returned ");
            return null;
        }

        // we assume BobSchulte camelcase usernames
        final String firstName = authenticatedUser[0].getString(3);
        final String lastName = authenticatedUser[0].getString(4);
        String fullUserName = firstName + lastName;
        LOGGER.warn("Got authenthicated user " + fullUserName);
        final String fullWikiName = "XWiki." + fullUserName;
        final String email = authenticatedUser[0].getString(13);
        if (findUser(fullUserName, context) == null) {
            // add this to xwiki.cfg: wiki.users.initialGroups=XWiki.XWikiAllGroup,XWiki.PCG-User
            createUser(fullUserName, firstName, lastName, authenticatedUser[1].getString(0) + " (" + system + ")", email, context);
        }

        wrappedRequest.setUserPrincipal(new SimplePrincipal(context.getWikiId() + ":" + fullUserName));
        return new XWikiUser(fullWikiName);
    }

    private static final String AUTH_URL = "https://oekobox-online.de/v3/shop/";

    /**
     * Do the actual oo call
     * @param system for dispatching the call
     * @param token  see description in oo:LPCGAuthenticator.java
     * @return a Json Array for a User Object per API (oekobox-online)
     */
    private JSONArray[] callOO(String system, String token) throws URISyntaxException, IOException {
        HttpClient httpClient = HttpClients.createDefault();
        HttpUriRequest loginRequest = RequestBuilder.post()
            .setUri(new URI(AUTH_URL + system + "/api/logon"))
            .addParameter("token", token).build();
        // should be a {action: "Logon", result: "<result>"}, see https://oekobox-online.de/shopdocu/wiki/API.methods.logon
        JSONObject loginResult = JSONObject.fromObject(getRemoteResponse(httpClient, loginRequest));
        LOGGER.warn("api/logon " + loginResult.toString()) ;
        String result = loginResult.getString("result");
        if (result == null || !result.equals("ok") && !result.equals("relogon")) {
            throw new ClientProtocolException("Authentication failed: " + result);
        }
        // fetch user info
        HttpUriRequest userDataRequest = RequestBuilder.post()
                    .setUri(new URI(AUTH_URL + system + "/api/user8")).build();
        JSONArray userDataResult = JSONArray.fromObject(getRemoteResponse(httpClient, userDataRequest));
        LOGGER.warn("api/user8 " + userDataResult.toString()) ;
        JSONArray ret = userDataResult.getJSONObject(0).getJSONArray("data").getJSONArray(0);
        LOGGER.warn("Parsed user to " + ret.toString()) ;
        // system name
        HttpUriRequest configRequest = RequestBuilder.post()
                    .setUri(new URI(AUTH_URL + system + "/api/configuration2")).build();
        JSONArray configResult = JSONArray.fromObject(getRemoteResponse(httpClient, configRequest));
        LOGGER.warn("api/configuration2 " + configResult.toString()) ;
        JSONArray ret1 = configResult.getJSONObject(0).getJSONArray("data").getJSONArray(0);
        LOGGER.warn("Parsed config to " + ret1.toString()) ;

        return new JSONArray[] {ret, ret1};
    }

    // helper to do a remote call
    private String getRemoteResponse(HttpClient httpClient, HttpUriRequest request) throws IOException {
        HttpResponse res = httpClient.execute(request);
        int status = res.getStatusLine().getStatusCode();
        if (status < 200 || status > 300) {
            throw new ClientProtocolException("Unexpected response status for logon call: " + status);
        }
        HttpEntity entity = res.getEntity();
        String callResponse = entity != null ? EntityUtils.toString(entity) : null;
        if (callResponse == null) {
            throw new ClientProtocolException("No response text");
        }
        return callResponse;
    }

    // clone of super to avoid touching another class. A bit DRY though
    protected String createUser(String user, String firstName, String lastName, String system, String email, XWikiContext context) throws XWikiException {
        String createuser = getParam("auth_createuser", context);

        LOGGER.warn("Create user param is " + createuser);
        LOGGER.warn("Createing " + user + "/" + system + "/" + email);

        if (createuser != null) {
            String wikiname = context.getWiki().clearName(user, true, true, context);
            XWikiDocument userdoc =
                    context.getWiki().getDocument(new DocumentReference(context.getWikiId(), "XWiki", wikiname), context);
            if (userdoc.isNew()) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("User page does not exist for user " + user);
                }

                if ("empty".equals(createuser)) {
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("Creating emptry user for user " + user);
                    }

                    Map<String, String> map = new HashMap<>();
                    map.put("active", "1");
                    map.put("first_name", firstName);
                    map.put("last_name", lastName);
                    map.put("company", system);
                    map.put("email", email);

                    if (context.getWiki().createUser(wikiname, map, "edit", context) == 1) {  // see config, to add the user to the right groups too
                        LOGGER.warn("Created user " + wikiname);
                    } else {
                        LOGGER.warn("Creating user failed" + wikiname);
                    }
                }
            } else {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("User page already exists for user " + user);
                }
            }

            return wikiname;
        }

        return user;
    }

    private SecurityRequestWrapper getSecurityRequestWrapper(XWikiContext context, HttpServletRequest req) throws XWikiException {
        XWikiAuthenticator auth = getAuthenticator(context);
        return new SecurityRequestWrapper(req, null, null, auth.getAuthMethod());
    }
}

