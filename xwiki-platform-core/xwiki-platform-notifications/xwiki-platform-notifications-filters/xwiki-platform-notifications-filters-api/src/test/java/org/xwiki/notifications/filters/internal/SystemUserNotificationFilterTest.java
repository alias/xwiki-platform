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

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.xwiki.eventstream.Event;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.notifications.NotificationFormat;
import org.xwiki.notifications.filters.NotificationFilterProperty;
import org.xwiki.notifications.filters.expression.NotEqualsNode;
import org.xwiki.notifications.filters.expression.PropertyValueNode;
import org.xwiki.notifications.filters.expression.StringValueNode;
import org.xwiki.notifications.filters.expression.generics.AbstractNode;
import org.xwiki.notifications.preferences.NotificationPreference;
import org.xwiki.test.mockito.MockitoComponentMockingRule;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SystemUserNotificationFilterTest
{
    @Rule
    public final MockitoComponentMockingRule<SystemUserNotificationFilter> mocker =
            new MockitoComponentMockingRule<>(SystemUserNotificationFilter.class);

    private EntityReferenceSerializer<String> entityReferenceSerializer;

    private Event nonSystemEvent;
    private Event systemEvent;

    private DocumentReference randomUser = new DocumentReference("xwiki", "XWiki", "alice");

    @Before
    public void setUp() throws Exception
    {
        DocumentReference systemUserReference = new DocumentReference("xwiki", "XWiki", "superadmin");
        DocumentReference randomUserReference = new DocumentReference("xwiki", "XWiki", "bob");

        entityReferenceSerializer =
                mocker.registerMockComponent(EntityReferenceSerializer.TYPE_STRING, "local");
        when(entityReferenceSerializer.serialize(
                eq(systemUserReference.getLocalDocumentReference()))).thenReturn("serializedSystemUser");

        nonSystemEvent = mock(Event.class);
        when(nonSystemEvent.getUser()).thenReturn(randomUserReference);

        systemEvent = mock(Event.class);
        when(systemEvent.getUser()).thenReturn(systemUserReference);
    }

    @Test
    public void filterEventByFilterType() throws Exception
    {
        assertFalse(mocker.getComponentUnderTest().filterEventByFilterType(nonSystemEvent, randomUser,
                NotificationFormat.ALERT, NotificationFilterType.EXCLUSIVE));
        assertFalse(mocker.getComponentUnderTest().filterEventByFilterType(nonSystemEvent, randomUser,
                NotificationFormat.ALERT, NotificationFilterType.INCLUSIVE));

        assertFalse(mocker.getComponentUnderTest().filterEventByFilterType(systemEvent, randomUser,
                NotificationFormat.ALERT, NotificationFilterType.INCLUSIVE));
        assertTrue(mocker.getComponentUnderTest().filterEventByFilterType(systemEvent, randomUser,
                NotificationFormat.ALERT, NotificationFilterType.EXCLUSIVE));
    }

    @Test
    public void generateFilterExpression() throws Exception
    {
        NotificationPreference fakePreference = mock(NotificationPreference.class);

        assertEquals(AbstractNode.EMPTY_NODE,
                mocker.getComponentUnderTest().generateFilterExpression(
                        randomUser, fakePreference, NotificationFilterType.INCLUSIVE));
        assertEquals(new NotEqualsNode(
                new PropertyValueNode(NotificationFilterProperty.USER),
                new StringValueNode("serializedSystemUser")),
                mocker.getComponentUnderTest().generateFilterExpression(
                        randomUser, fakePreference, NotificationFilterType.EXCLUSIVE));
    }

    @Test
    public void matchesPreference() throws Exception
    {
        assertTrue(mocker.getComponentUnderTest().matchesPreference(mock(NotificationPreference.class)));
    }
}
