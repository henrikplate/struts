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
package org.apache.struts2.views.jsp.ui;

import org.apache.struts2.util.ValueStack;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.struts2.components.Component;
import org.apache.struts2.components.TextArea;

import java.io.Serial;

/**
 * @see TextArea
 */
public class TextareaTag extends AbstractUITag {

    @Serial
    private static final long serialVersionUID = -4107122506712927927L;

    protected String cols;
    protected String readonly;
    protected String rows;
    protected String wrap;
    protected String maxlength;
    protected String minlength;

    @Override
    public Component getBean(ValueStack stack, HttpServletRequest req, HttpServletResponse res) {
        return new TextArea(stack, req, res);
    }

    @Override
    protected void populateParams() {
        super.populateParams();

        TextArea textArea = ((TextArea) component);
        textArea.setCols(cols);
        textArea.setReadonly(readonly);
        textArea.setRows(rows);
        textArea.setWrap(wrap);
        textArea.setMaxlength(maxlength);
        textArea.setMinlength(minlength);
    }

    public void setCols(String cols) {
        this.cols = cols;
    }

    public void setReadonly(String readonly) {
        this.readonly = readonly;
    }

    public void setRows(String rows) {
        this.rows = rows;
    }

    public void setWrap(String wrap) {
        this.wrap = wrap;
    }

    public void setMaxlength(String maxlength) {
        this.maxlength = maxlength;
    }

    public void setMinlength(String minlength) {
        this.minlength = minlength;
    }

    /**
     * Must declare the setter at the descendant Tag class level in order for the tag handler to locate the method.
     */
    @Override
    public void setPerformClearTagStateForTagPoolingServers(boolean performClearTagStateForTagPoolingServers) {
        super.setPerformClearTagStateForTagPoolingServers(performClearTagStateForTagPoolingServers);
    }

    @Override
    protected void clearTagStateForTagPoolingServers() {
       if (!getPerformClearTagStateForTagPoolingServers()) {
            return;  // If flag is false (default setting), do not perform any state clearing.
        }
        super.clearTagStateForTagPoolingServers();
        this.cols = null;
        this.readonly = null;
        this.rows = null;
        this.wrap = null;
        this.maxlength = null;
        this.minlength = null;
    }

}
