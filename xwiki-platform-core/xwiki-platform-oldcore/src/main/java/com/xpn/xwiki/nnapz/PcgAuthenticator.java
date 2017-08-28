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
 * Use xwiki.authentication.authclass=com.xpn.xwiki.nnapz.PcgAuthenticator in config
 * Change logon form ./skins/flamingo/login.vm to add usepcg checkbox
 *
 * @author Bob Schulze
 * @version $Id$
 * @since 9.6.x
 */
public class PcgAuthenticator extends XWikiAuthServiceImpl {

    private static final Logger LOGGER = LoggerFactory.getLogger(PcgAuthenticator.class);   // use warn only to avoid fiddling with log settings ;-)

    @Override
    public XWikiUser checkAuth(XWikiContext context) throws XWikiException {
        final HttpServletRequest req = context.getRequest().getHttpServletRequest();

        //LOGGER.warn("*** CTX user: " + context.getUserReference());
        boolean usepcg = req.getParameter("usepcg") != null;
        final String j_username = req.getParameter("j_username");
        final String j_password = req.getParameter("j_password");
        String token = req.getParameter("oo-token");
        String system = req.getParameter("oo-system");

        LOGGER.warn("*** checkAuth: " + usepcg + "/" + j_username + "/" + token + "/" + system);
        // are we in a regular form authentication or any other auth action that we better do not interfere?
        if (req.getPathInfo().toLowerCase().contains("logout")) {
            LOGGER.warn("logout activity, delegate to parent " + super.getClass());
            return super.checkAuth(context);
        }

        // try own checks
        SecurityRequestWrapper wrappedRequest = getSecurityRequestWrapper(context, req);
        if (token == null && !usepcg) {
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

        // are we in a regular form authentication or any other auth action that we better do not interfere?
       if (!usepcg && (j_username != null || req.getParameter("srid") != null)) {
           LOGGER.warn("auth activity, delegate to parent " + super.getClass());
           return super.checkAuth(context);
       }

        // some validation
        if (token != null && token.length() > 300) {
            LOGGER.error("Token has unusual size, abort");
            return null;
        }

        // lets try pcg auth
        if (usepcg) {
            LOGGER.warn("Getting PCG Auth for U/P " + j_username + "/" + j_password + " - Wiki " + context.getWikiId());
        } else {
            LOGGER.warn("Getting PCG Auth for " + token + " Wiki " + context.getWikiId());
            if (system == null || system.trim().length() == 0) {
               LOGGER.error("oo-system parameter missing. Ignore auth request.");
               return null;
           }
        }

        String server = req.getParameter("oo-server");
        if (server == null || server.trim().length() == 0) {
            LOGGER.warn("oo-server parameter missing. use de.");
            server = "oekobox-online.de";
        }

        // API call to oo
        JSONArray[] authenticatedUser;
        try {
            authenticatedUser = callOO(server, system, token, j_username, j_password);   // if there is a token we use token auth, else u/p
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

        // we assume BobSchulze camelcase usernames
        final String firstName = authenticatedUser[0].getString(3);
        final String lastName = authenticatedUser[0].getString(4);
        String fullUserName = replaceUmlauts(firstName + lastName);
        LOGGER.warn("check user " + fullUserName);
        final String fullWikiName = "XWiki." + fullUserName;
        final String email = authenticatedUser[0].getString(13);
        if (findUser(fullUserName, context) == null) {
            // add this to xwiki.cfg: wiki.users.initialGroups=XWiki.XWikiAllGroup,XWiki.PCG-User
            createUser(fullUserName, firstName, lastName, authenticatedUser[1].getString(0) + " (" + system + ")", email, context);
        }

        wrappedRequest.setUserPrincipal(new SimplePrincipal(context.getWikiId() + ":" + fullUserName));
        return new XWikiUser(fullWikiName);
    }

    private String replaceUmlauts(String s) {
        return s.replace("Ö", "Oe").replace("ö", "oe")
         .replace("Ü", "Ue").replace("ü", "ue")
         .replace("Ä", "Ae").replace("ä", "ae")
         .replace("ß", "ss");
    }

    /**
     * Do the actual oo call. If token != null, we use token, else the username and passwd
     * @param server the server to contact 
     * @param system for dispatching the call
     * @param token  see description in oo:LPCGAuthenticator.java
     * @param userName optional the username
     * @param pass optional the passwd
     * @return a Json Array for a User Object per API (oekobox-online)
     */
    private JSONArray[] callOO(String server, String system, String token, String userName, String pass) throws URISyntaxException, IOException {
        HttpClient httpClient = HttpClients.createDefault();

        if (system == null) {
            HttpUriRequest bindRequest = RequestBuilder.get("https://" + server + "/v3/bind1/" + userName).build();  // userName is expected to be the email
            JSONArray bindResult = JSONArray.fromObject(getRemoteResponse(httpClient, bindRequest));
            LOGGER.warn("api/bind " + bindResult.toString()) ;
            JSONArray sysInfo = getFirstDataRow(bindResult);
            system = sysInfo.getString(5);
            LOGGER.warn("api/bound to " + system);
        }
        final String baseUrl = "https://" + server + "/v3/shop/" + system;
        HttpUriRequest loginRequest = token != null ?
                RequestBuilder.post()
                    .setUri(new URI(baseUrl + "/api/logon"))
                    .addParameter("token", token).build() :
                RequestBuilder.post()
                    .setUri(new URI(baseUrl + "/api/logon"))
                    .addParameter("cid", userName).addParameter("pass", pass).build();

        // should be a {action: "Logon", result: "<result>"}, see https://oekobox-online.de/shopdocu/wiki/API.methods.logon
        JSONObject loginResult = JSONObject.fromObject(getRemoteResponse(httpClient, loginRequest));
        LOGGER.warn("api/logon " + loginResult.toString()) ;
        String result = loginResult.getString("result");
        if (result == null || !result.equals("ok") && !result.equals("relogon")) {
            throw new ClientProtocolException("Authentication failed: " + result);
        }
        // fetch user info
        HttpUriRequest userDataRequest = RequestBuilder.post()
                    .setUri(new URI(baseUrl + "/api/user8")).build();
        JSONArray userDataResult = JSONArray.fromObject(getRemoteResponse(httpClient, userDataRequest));
        LOGGER.warn("api/user8 " + userDataResult.toString()) ;
        JSONArray ret = getFirstDataRow(userDataResult);
        LOGGER.warn("Parsed user to " + ret.toString()) ;
        // system name
        HttpUriRequest configRequest = RequestBuilder.post()
                    .setUri(new URI(baseUrl+ "/api/configuration2")).build();
        JSONArray configResult = JSONArray.fromObject(getRemoteResponse(httpClient, configRequest));
        LOGGER.warn("api/configuration2 " + configResult.toString()) ;
        JSONArray ret1 = getFirstDataRow(configResult);
        LOGGER.warn("Parsed config to " + ret1.toString()) ;

        return new JSONArray[] {ret, ret1};
    }

    private JSONArray getFirstDataRow(JSONArray jsonResult) {
        return jsonResult.getJSONObject(0).getJSONArray("data").getJSONArray(0);
    }

    // helper to do a remote call
    private String getRemoteResponse(HttpClient httpClient, HttpUriRequest request) throws IOException {
        HttpResponse res = httpClient.execute(request);
        int status = res.getStatusLine().getStatusCode();
        if (status < 200 || status > 300) {
            throw new ClientProtocolException("Unexpected response status for call to " + request.getURI() + ": " + status);
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

