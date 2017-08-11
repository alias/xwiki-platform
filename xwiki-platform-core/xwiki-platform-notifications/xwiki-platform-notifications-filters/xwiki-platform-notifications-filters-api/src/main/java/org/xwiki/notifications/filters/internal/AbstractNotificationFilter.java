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

import org.xwiki.eventstream.Event;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.notifications.NotificationFormat;
import org.xwiki.notifications.filters.NotificationFilter;
import org.xwiki.notifications.filters.expression.AndNode;
import org.xwiki.notifications.filters.expression.generics.AbstractNode;
import org.xwiki.notifications.preferences.NotificationPreference;

/**
 * This is a generic definition of the methods that a {@link NotificationFilter} can provide.
 *
 * @version $Id$
 * @since 9.7RC1
 */
public abstract class AbstractNotificationFilter implements NotificationFilter
{
    @Override
    public boolean filterEvent(Event event, DocumentReference user, NotificationFormat format)
    {
        return this.filterEventByFilterType(event, user, format, NotificationFilterType.EXCLUSIVE)
                || this.filterEventByFilterType(event, user, format, NotificationFilterType.INCLUSIVE);
    }

    @Override
    public AbstractNode filterExpression(DocumentReference user, NotificationPreference preference)
    {
        AbstractNode leftOperand = this.generateFilterExpression(user, preference,
                NotificationFilterType.INCLUSIVE);
        AbstractNode rightOperand = this.generateFilterExpression(user, preference,
                NotificationFilterType.EXCLUSIVE);

        if (leftOperand.equals(AbstractNode.EMPTY_NODE)) {
            return rightOperand;
        } else if (rightOperand.equals(AbstractNode.EMPTY_NODE)) {
            return leftOperand;
        } else {
            return new AndNode(leftOperand, rightOperand);
        }
    }

    /**
     * Just as {@link #filterEvent(Event, DocumentReference, NotificationFormat)}, use the given user, the event, the
     * format of the wanted notification and the type of filter we want to apply (see
     * {@link NotificationFilterType}) to determine if the given event should be dismissed.
     *
     * @return true if the event should be dismissed
     * @since 9.7RC1
     */
    protected abstract boolean filterEventByFilterType(Event event, DocumentReference user, NotificationFormat format,
            NotificationFilterType filterType);

    /**
     * Generate parts of an abstract syntax tree (AST) used to retrieve events from a given user.
     * Depending on the {@link NotificationFilterType} given, the generated AST will have a different
     * content.
     *
     * Generated AST for INCLUSIVE filters:
     * (--filter1--) OR (--filter2--) OR (--filter3--) ...
     *
     * Generated AST for EXCLUSIVE filters:
     * NOT (--filter1--) AND NOT (--filter2--) AND NOT (--filter3--) ...
     *
     * @since 9.7RC1
     */
    protected abstract AbstractNode generateFilterExpression(DocumentReference user, NotificationPreference preference,
            NotificationFilterType filterType);
}
