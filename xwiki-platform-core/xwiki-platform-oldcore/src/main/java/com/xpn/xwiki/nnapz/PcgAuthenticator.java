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
 * The token is forward to auth in oekobox-online.de. If that succeeds, the returned user information is used to look
 * up the local user. If that does not exist yet, we create it and set it to the Role "Anwender".
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
 * @author Bob Schulze
 * @version $Id$
 * @since 9.6.x
 */
public class PcgAuthenticator extends XWikiAuthServiceImpl {

    /**
     * Lawg dawg.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(PcgAuthenticator.class);


    @Override
    public XWikiUser checkAuth(XWikiContext context) throws XWikiException {
        final HttpServletRequest req = context.getRequest().getHttpServletRequest();

        LOGGER.warn("*** CTX user: " + context.getUserReference());

        /*
        HttpSession session = req.getSession(false);
        if (session == null) {
            LOGGER.warn("No session");
        } else {
            Enumeration sps = session.getAttributeNames();
            while (sps.hasMoreElements()) {
                String pn = (String) sps.nextElement();
                try {
                    LOGGER.warn("   " + pn + ": " + session.getAttribute(pn).getClass());
                } catch (Throwable twb) {
                    LOGGER.warn("   " + pn + ": (unreadable: " + twb.getMessage() + ")");
                }
            }
        }
        */
        // are we a regular form authentication or any other auth action that we better do not interfere?
        if (req.getParameter("j_username") != null || req.getParameter("srid") != null
                 || req.getPathInfo().toLowerCase().contains("logout")) {
            LOGGER.warn("auth activity, delegate to parent " + super.getClass());
            return super.checkAuth(context);
        }
        // try our token
        String token = req.getParameter("oo-token");
        // some validation
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
        if (token.length() > 300) {
            LOGGER.error("Token has unusual size, abort");
            return null;
        }
        // else create and store to session
        LOGGER.warn("Getting PCG Auth for " + token + " Wiki " + context.getWikiId());
        String system = req.getParameter("oo-system");
        if (system == null || system.trim().length() == 0) {
            LOGGER.error("oo-system parameter missing. Ignore auth request.");
            return null;
        }
        // API call to oo
        JSONArray authenticatedUser;
        try {
            authenticatedUser = callOO(system, token);
        } catch (URISyntaxException e) {
            LOGGER.error("Wrong URL for " + system + ": " + e.getMessage());
            return null;
        } catch (IOException e) {
            LOGGER.error("Call failed for " + system + ": " + e.getMessage());
            return null;
        }
        if (authenticatedUser == null) {
            LOGGER.error("Call failed for " + system + ": no data returned ");
            return null;
        }
        // we assume BobSchulte camelcase usernames
        final String firstName = authenticatedUser.getString(3);
        final String lastName = authenticatedUser.getString(4);
        String fullUserName = firstName + lastName;
        LOGGER.warn("Got authenthicated user " + fullUserName);
        final String fullWikiName = "XWiki." + fullUserName;

        if (findUser(fullUserName, context) == null) {
            // add this to xwiki.cfg: wiki.users.initialGroups=XWiki.XWikiAllGroup,XWiki.PCG-User
            createUser(fullUserName, firstName, lastName, system, context);
        }

        wrappedRequest.setUserPrincipal(new SimplePrincipal(context.getWikiId() + ":" + fullUserName));
        return new XWikiUser(fullWikiName);
    }

    private static final String AUTH_URL = "https://oekobox-online.de/v3/shop/";

    private JSONArray callOO(String system, String token) throws URISyntaxException, IOException {
        HttpClient httpClient = HttpClients.createDefault();
        HttpUriRequest loginRequest = RequestBuilder.post()
            .setUri(new URI(AUTH_URL + system + "/api/logon"))
            .addParameter("token", token).build();
        // should be a {action: "Logon", result: "<result>"}, see https://oekobox-online.de/shopdocu/wiki/API.methods.logon
        JSONObject loginResult = getRemoteResponse(httpClient, loginRequest);
        LOGGER.warn("api/logon " + loginResult.toString()) ;
        String result = loginResult.getString("result");
        if (result == null || !result.equals("ok") && !result.equals("relogon")) {
            throw new ClientProtocolException("Authentication failed: " + result);
        }
        // fetch user info
        HttpUriRequest userDataRequest = RequestBuilder.post()
                    .setUri(new URI(AUTH_URL + system + "/api/user")).build();
        JSONObject userDataResult = getRemoteResponse(httpClient, userDataRequest);
        LOGGER.warn("api/user " + userDataResult.toString()) ;
        JSONArray ret = userDataResult.getJSONArray("data").getJSONArray(0);
        LOGGER.warn("Parsed to " + ret.toString()) ;
        return ret;
    }

    private JSONObject getRemoteResponse(HttpClient httpClient, HttpUriRequest request) throws IOException {
        HttpResponse res = httpClient.execute(request);
        int status = res.getStatusLine().getStatusCode();
        if (status < 200 || status > 300) {
            throw new ClientProtocolException("Unexpected response status for logon call: " + status);
        }
        HttpEntity entity = res.getEntity();
        String authResponse = entity != null ? EntityUtils.toString(entity) : null;
        if (authResponse == null) {
            throw new ClientProtocolException("No response text");
        }
        return JSONObject.fromObject(authResponse);
    }

    // clone of super
    protected String createUser(String user, String firstName, String lastName, String system, XWikiContext context) throws XWikiException {
        String createuser = getParam("auth_createuser", context);

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Create user param is " + createuser);
        }

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

                    if (context.getWiki().createUser(wikiname, map, "edit", context) == 1) {
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

