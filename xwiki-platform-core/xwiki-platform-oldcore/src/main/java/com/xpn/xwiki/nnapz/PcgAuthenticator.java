package com.xpn.xwiki.nnapz;


import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.user.api.XWikiUser;
import com.xpn.xwiki.user.impl.xwiki.XWikiAuthServiceImpl;
import com.xpn.xwiki.user.impl.xwiki.XWikiAuthenticator;
import org.securityfilter.filter.SecurityRequestWrapper;
import org.securityfilter.realm.SimplePrincipal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;

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

        LOGGER.warn("***++ CTX user: " + context.getUserReference());

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
        // else create and store to session
        LOGGER.warn("Getting PCG Auth for " + token + " Wiki " + context.getWikiId());
        String system = req.getParameter("oo-system");
        if (system == null || system.trim().length() == 0) {
            LOGGER.error("oo-system parameter missing. Ignore auth request.");
            return null;
        }
        // API call to oo

        String name = token;
        final String fullName = "XWiki." + name;

        createUserIfNeeded(name, fullName, context);

        wrappedRequest.setUserPrincipal(new SimplePrincipal(context.getWikiId() + ":" + name));
        return new XWikiUser(fullName);
    }

    private SecurityRequestWrapper getSecurityRequestWrapper(XWikiContext context, HttpServletRequest req) throws XWikiException {
        XWikiAuthenticator auth = getAuthenticator(context);
        return new SecurityRequestWrapper(req, null, null, auth.getAuthMethod());
    }

    /**
     * Create a user if none exists.
     *
     * @param name     the short name, must be scrubbed of chars which XWiki doesn't like.
     * @param fullName name, prefixed with 'XWiki.'.
     * @param context  the ball of mud.
     * @throws XWikiException if thrown by {@link XWiki()}.
     */
    private void createUserIfNeeded(final String name,
                                    final String fullName,
                                    final XWikiContext context) throws XWikiException {
        final String database = context.getDatabase();
        try {
            // Switch to main wiki to force users to be global users
            context.setDatabase(context.getMainXWiki());

            final XWiki wiki = context.getWiki();

            // test if user already exists
            if (!wiki.exists(fullName, context)) {
                LOGGER.info("Need to create user [{0}]", fullName);
                wiki.createEmptyUser(name, "edit", context);
            }
        } finally {
            context.setDatabase(database);
        }
    }
}

