/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.notifications.filters.internal;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.model.ModelContext;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.WikiReference;
import org.xwiki.notifications.NotificationException;
import org.xwiki.notifications.filters.NotificationFilter;
import org.xwiki.notifications.filters.NotificationFilterManager;
import org.xwiki.notifications.preferences.NotificationPreference;
import org.xwiki.wiki.descriptor.WikiDescriptorManager;

/**
 * Default implementation of {@link NotificationFilterManager}.
 *
 * @version $Id$
 * @since 9.5RC1
 */
@Component
@Singleton
public class DefaultNotificationFilterManager implements NotificationFilterManager
{
    private static final String ERROR_MESSAGE = "Failed to get all the notification filters.";

    @Inject
    private ComponentManager componentManager;

    @Inject
    private WikiDescriptorManager wikiDescriptorManager;

    @Inject
    private ModelContext modelContext;

    @Inject
    @Named("cached")
    private ModelBridge modelBridge;

    @Override
    public Set<NotificationFilter> getAllFilters(DocumentReference user)
            throws NotificationException
    {
        // If the user is from the main wiki, get filters from all wikis
        if (user.getWikiReference().getName().equals(wikiDescriptorManager.getMainWikiId())) {

            String currentWikiId = wikiDescriptorManager.getCurrentWikiId();

            Map<String, NotificationFilter> filters = new HashMap<>();
            try {
                for (String wikiId : wikiDescriptorManager.getAllIds()) {
                    modelContext.setCurrentEntityReference(new WikiReference(wikiId));

                    filters.putAll(componentManager.getInstanceMap(NotificationFilter.class));
                }
            } catch (Exception e) {
                throw new NotificationException(ERROR_MESSAGE, e);
            } finally {
                modelContext.setCurrentEntityReference(new WikiReference(currentWikiId));
            }

            return removeDisabledFilters(user, new HashSet<>(filters.values()));
        } else {
            // If the user is local, get filters from the current wiki only (we assume it's the wiki of the user).
            try {
                return removeDisabledFilters(user,
                        new HashSet<>(componentManager.getInstanceList(NotificationFilter.class)));
            }  catch (Exception e) {
                throw new NotificationException(ERROR_MESSAGE, e);
            }
        }
    }

    @Override
    public Set<NotificationFilter> getFilters(DocumentReference user,
            NotificationPreference preference) throws NotificationException
    {
        Set<NotificationFilter> filters = getAllFilters(user);

        Iterator<NotificationFilter> it = filters.iterator();

        while (it.hasNext()) {
            NotificationFilter filter = it.next();

            if (!filter.matchesPreference(preference)) {
                it.remove();
            }
        }

        return filters;
    }

    /**
     * Goes through every given {@link NotificationFilter}. One of the filters implements
     * {@link ToggleableNotificationFilter}, checks if the given user has disabled this filter. If so, remove the
     * filter from the set.
     *
     * @param user the user to use
     * @param filters the filters that should be examined
     * @return a set of filters that are not marked as disabled by the user
     * @throws NotificationException if an error occurs
     *
     * @since 9.7RC1
     */
    private Set<NotificationFilter> removeDisabledFilters(DocumentReference user, Set<NotificationFilter> filters)
            throws NotificationException
    {
        Iterator<NotificationFilter> it = filters.iterator();

        Set<String> disabledFiltersHints = modelBridge.getDisabledNotificationFiltersHints(user);

        while (it.hasNext()) {
            NotificationFilter filter = it.next();

            if (filter.getClass().isAnnotationPresent(ToggleableNotificationFilter.class)
                    && disabledFiltersHints.contains(
                            filter.getClass().getAnnotation(ToggleableNotificationFilter.class).value())) {
                it.remove();
            }
        }

        return filters;
    }
}
