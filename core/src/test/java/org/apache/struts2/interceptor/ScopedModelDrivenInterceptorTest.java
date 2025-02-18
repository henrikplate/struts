/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.struts2.interceptor;

import org.apache.struts2.action.Action;
import org.apache.struts2.ActionContext;
import org.apache.struts2.ObjectFactory;
import org.apache.struts2.ProxyObjectFactory;
import org.apache.struts2.SimpleAction;
import org.apache.struts2.XWorkTestCase;
import org.apache.struts2.config.entities.ActionConfig;
import org.apache.struts2.mock.MockActionInvocation;
import org.apache.struts2.mock.MockActionProxy;
import org.apache.struts2.test.Equidae;
import org.apache.struts2.test.User;

import java.util.HashMap;
import java.util.Map;

public class ScopedModelDrivenInterceptorTest extends XWorkTestCase {

    protected ScopedModelDrivenInterceptor inter = null;

    /**
     * Set up instance variables required by this test case.
     */
    @Override
    public void setUp() throws Exception {
        super.setUp();
        inter = new ScopedModelDrivenInterceptor();
        ProxyObjectFactory factory = new ProxyObjectFactory();
        factory.setContainer(container);
        inter.setObjectFactory(factory);
    }

    public void testResolveModel() throws Exception {
        ActionContext ctx = ActionContext.getContext().withSession(new HashMap<>());

        ObjectFactory factory = ActionContext.getContext().getContainer().getInstance(ObjectFactory.class);
        Object obj = inter.resolveModel(factory, ctx, "java.lang.String", "request", "foo");
        assertNotNull(obj);
        assertTrue(obj instanceof String);
        assertSame(obj, ctx.get("foo"));

        obj = inter.resolveModel(factory, ctx, "java.lang.String", "session", "foo");
        assertNotNull(obj);
        assertTrue(obj instanceof String);
        assertSame(obj, ctx.getSession().get("foo"));

        obj = inter.resolveModel(factory, ctx, "java.lang.String", "session", "foo");
        assertNotNull(obj);
        assertTrue(obj instanceof String);
        assertSame(obj, ctx.getSession().get("foo"));
    }

    public void testScopedModelDrivenAction() throws Exception {
        inter.setScope("request");

        ScopedModelDriven action = new MyUserScopedModelDrivenAction();
        MockActionInvocation mai = new MockActionInvocation();
        MockActionProxy map = new MockActionProxy();
        ActionConfig ac = new ActionConfig.Builder("", "", "").build();
        map.setConfig(ac);
        mai.setAction(action);
        mai.setProxy(map);

        inter.intercept(mai);
        inter.destroy();

        assertNotNull(action.getModel());
        assertNotNull(action.getScopeKey());
        assertEquals("org.apache.struts2.test.User", action.getScopeKey());

        Object model = ActionContext.getContext().get(action.getScopeKey());
        assertNotNull(model);
        assertTrue("Model should be an User object", model instanceof User);
    }

    public void testScopedModelDrivenActionWithSetClassName() throws Exception {
        inter.setScope("request");
        inter.setClassName("org.apache.struts2.test.Equidae");
        inter.setName("queen");

        ScopedModelDriven action = new MyEquidaeScopedModelDrivenAction();
        MockActionInvocation mai = new MockActionInvocation();
        MockActionProxy map = new MockActionProxy();
        ActionConfig ac = new ActionConfig.Builder("", "", "").build();
        map.setConfig(ac);
        mai.setAction(action);
        mai.setProxy(map);

        inter.intercept(mai);
        inter.destroy();

        assertNotNull(action.getModel());
        assertNotNull(action.getScopeKey());
        assertEquals("queen", action.getScopeKey());

        Object model = ActionContext.getContext().get(action.getScopeKey());
        assertNotNull(model);
        assertTrue("Model should be an Equidae object", model instanceof Equidae);
    }

    public void testModelOnSession() throws Exception {
        inter.setScope("session");
        inter.setName("king");

        User user = new User();
        user.setName("King George");
        Map session = new HashMap();
        ActionContext.getContext().withSession(session);
        ActionContext.getContext().getSession().put("king", user);

        ScopedModelDriven action = new MyUserScopedModelDrivenAction();
        MockActionInvocation mai = new MockActionInvocation();
        MockActionProxy map = new MockActionProxy();
        ActionConfig ac = new ActionConfig.Builder("", "", "").build();
        map.setConfig(ac);
        mai.setAction(action);
        mai.setProxy(map);

        inter.intercept(mai);
        inter.destroy();

        assertNotNull(action.getModel());
        assertNotNull(action.getScopeKey());
        assertEquals("king", action.getScopeKey());

        Object model = ActionContext.getContext().getSession().get(action.getScopeKey());
        assertNotNull(model);
        assertTrue("Model should be an User object", model instanceof User);
        assertEquals("King George", ((User) model).getName());
    }

    public void testModelAlreadySetOnAction() throws Exception {
        inter.setScope("request");
        inter.setName("king");

        User user = new User();
        user.setName("King George");

        ScopedModelDriven action = new MyUserScopedModelDrivenAction();
        action.setModel(user);
        MockActionInvocation mai = new MockActionInvocation();
        MockActionProxy map = new MockActionProxy();
        ActionConfig ac = new ActionConfig.Builder("", "", "").build();
        map.setConfig(ac);
        mai.setAction(action);
        mai.setProxy(map);

        inter.intercept(mai);
        inter.destroy();

        assertNotNull(action.getModel());
        assertNull(action.getScopeKey()); // no scope key as nothing happended
    }

    public void testNoScopedModelAction() throws Exception {
        Action action = new SimpleAction();
        MockActionInvocation mai = new MockActionInvocation();
        MockActionProxy map = new MockActionProxy();
        ActionConfig ac = new ActionConfig.Builder("", "", "").build();
        map.setConfig(ac);
        mai.setAction(action);
        mai.setProxy(map);

        inter.intercept(mai);
        inter.destroy();
        // nothing happends
    }

    private class MyUserScopedModelDrivenAction implements ScopedModelDriven, Action {

        private String key;
        private User model;

        @Override
        public void setModel(Object model) {
            this.model = (User) model;
        }

        @Override
        public void setScopeKey(String key) {
            this.key = key;
        }

        @Override
        public String getScopeKey() {
            return key;
        }

        @Override
        public User getModel() {
            return model;
        }

        @Override
        public String execute() throws Exception {
            return SUCCESS;
        }

    }

    private class MyEquidaeScopedModelDrivenAction implements ScopedModelDriven, Action {

        private String key;
        private Equidae model;

        @Override
        public void setModel(Object model) {
            this.model = (Equidae) model;
        }

        @Override
        public void setScopeKey(String key) {
            this.key = key;
        }

        @Override
        public String getScopeKey() {
            return key;
        }

        @Override
        public Equidae getModel() {
            return model;
        }

        @Override
        public String execute() throws Exception {
            return SUCCESS;
        }

    }

}

