/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/*
* This file was automatically generated by Autotag.  Please do not edit it manually.
*/
package org.apache.tiles.web.jsp.taglib;

import java.io.IOException;

import jakarta.servlet.jsp.JspException;
import jakarta.servlet.jsp.tagext.SimpleTagSupport;

import org.apache.tiles.autotag.core.runtime.ModelBody;
import org.apache.tiles.autotag.core.runtime.AutotagRuntime;

/**
 * <p>
 * Create a definition at runtime.
 * </p>
 * <p>
 * Create a new definition at runtime. Newly created definition will be
 * available across the entire request.
 * </p>
 */
public class DefinitionTag extends SimpleTagSupport {

    /**
     * The template model.
     */
    private org.apache.tiles.template.DefinitionModel model = new org.apache.tiles.template.DefinitionModel();

    /**
     * The name of the definition to create. If not specified, an anonymous
     * definition will be created.
     */
    private java.lang.String name;

    /**
     * The template of this definition.
     */
    private java.lang.String template;

    /**
     * A comma-separated list of roles. If present, the definition will be rendered
     * only if the current user belongs to one of the roles.
     */
    private java.lang.String role;

    /**
     * The definition name that this definition extends.
     */
    private java.lang.String extendsParam;

    /**
     * The preparer to use to invoke before the definition is rendered.
     */
    private java.lang.String preparer;

    /**
     * Getter for name property.
     *
     * @return The name of the definition to create. If not specified, an anonymous
     *         definition will be created.
     */
    public java.lang.String getName() {
        return name;
    }

    /**
     * Setter for name property.
     *
     * @param name The name of the definition to create. If not specified, an
     *             anonymous definition will be created.
     */
    public void setName(java.lang.String name) {
        this.name = name;
    }

    /**
     * Getter for template property.
     *
     * @return The template of this definition.
     */
    public java.lang.String getTemplate() {
        return template;
    }

    /**
     * Setter for template property.
     *
     * @param template The template of this definition.
     */
    public void setTemplate(java.lang.String template) {
        this.template = template;
    }

    /**
     * Getter for role property.
     *
     * @return A comma-separated list of roles. If present, the definition will be
     *         rendered only if the current user belongs to one of the roles.
     */
    public java.lang.String getRole() {
        return role;
    }

    /**
     * Setter for role property.
     *
     * @param role A comma-separated list of roles. If present, the definition will
     *             be rendered only if the current user belongs to one of the roles.
     */
    public void setRole(java.lang.String role) {
        this.role = role;
    }

    /**
     * Getter for extends property.
     *
     * @return The definition name that this definition extends.
     */
    public java.lang.String getExtends() {
        return extendsParam;
    }

    /**
     * Setter for extends property.
     *
     * @param extendsParam The definition name that this definition extends.
     */
    public void setExtends(java.lang.String extendsParam) {
        this.extendsParam = extendsParam;
    }

    /**
     * Getter for preparer property.
     *
     * @return The preparer to use to invoke before the definition is rendered.
     */
    public java.lang.String getPreparer() {
        return preparer;
    }

    /**
     * Setter for preparer property.
     *
     * @param preparer The preparer to use to invoke before the definition is
     *                 rendered.
     */
    public void setPreparer(java.lang.String preparer) {
        this.preparer = preparer;
    }

    @Override
    public void doTag() throws JspException, IOException {
        AutotagRuntime<org.apache.tiles.request.Request> runtime = new org.apache.tiles.request.jsp.autotag.JspAutotagRuntime();
        if (runtime instanceof SimpleTagSupport) {
            SimpleTagSupport tag = (SimpleTagSupport) runtime;
            tag.setJspContext(getJspContext());
            tag.setJspBody(getJspBody());
            tag.setParent(getParent());
            tag.doTag();
        }
        org.apache.tiles.request.Request request = runtime.createRequest();
        ModelBody modelBody = runtime.createModelBody();
        model.execute(name, template, role, extendsParam, preparer, request, modelBody);
    }
}
