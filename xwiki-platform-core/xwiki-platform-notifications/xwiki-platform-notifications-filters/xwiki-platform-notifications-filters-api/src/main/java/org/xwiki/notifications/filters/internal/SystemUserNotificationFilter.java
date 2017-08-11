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

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.eventstream.Event;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.model.reference.LocalDocumentReference;
import org.xwiki.notifications.NotificationFormat;
import org.xwiki.notifications.filters.NotificationFilterProperty;
import org.xwiki.notifications.filters.expression.NotEqualsNode;
import org.xwiki.notifications.filters.expression.PropertyValueNode;
import org.xwiki.notifications.filters.expression.StringValueNode;
import org.xwiki.notifications.filters.expression.generics.AbstractNode;
import org.xwiki.notifications.preferences.NotificationPreference;

/**
 * Define notification filters that are activated by default on every user and that filter the notifications
 * coming from the system user.
 *
 * @version $Id$
 * @since 9.7RC1
 */
@Component
@Singleton
@Named(SystemUserNotificationFilter.FILTER_NAME)
@ToggleableNotificationFilter(SystemUserNotificationFilter.FILTER_NAME)
public class SystemUserNotificationFilter extends AbstractNotificationFilter
{
    /**
     * The name of the filter.
     */
    public static final String FILTER_NAME = "systemUserNotificationFilter";

    @Inject
    @Named("local")
    private EntityReferenceSerializer<String> serializer;

    /**
     * Local document reference to the system user.
     */
    private final LocalDocumentReference systemUser =
            new LocalDocumentReference("XWiki", "superadmin");

    @Override
    protected boolean filterEventByFilterType(Event event, DocumentReference user, NotificationFormat format,
            NotificationFilterType filterType)
    {
        if (filterType.equals(NotificationFilterType.EXCLUSIVE)) {
            return (event.getUser().getLocalDocumentReference().equals(systemUser));
        } else {
            return false;
        }
    }

    @Override
    protected AbstractNode generateFilterExpression(DocumentReference user, NotificationPreference preference,
            NotificationFilterType filterType)
    {
        if (filterType.equals(NotificationFilterType.EXCLUSIVE)) {
            return new NotEqualsNode(
                    new PropertyValueNode(NotificationFilterProperty.USER),
                    new StringValueNode(serializer.serialize(systemUser)));
        } else {
            return AbstractNode.EMPTY_NODE;
        }
    }

    @Override
    public boolean matchesPreference(NotificationPreference preference)
    {
        // This filter is applied globally to every notification preference, therefore, we match all of them.
        return true;
    }
}
