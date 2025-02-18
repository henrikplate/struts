<#--
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
-->
<#--
	Only show message if errors are available.
	This will be done if ActionSupport is used.
-->
<#assign hasFieldErrors = attributes.name?? && fieldErrors?? && fieldErrors.get(attributes.name)??/>
<#if (attributes.errorposition!"top") == 'top'>
<#if hasFieldErrors>
<#list fieldErrors.get(attributes.name) as error>
<tr errorFor="${attributes.id}">
    <td class="tdErrorMessage" colspan="2"><#rt/>
        <span class="errorMessage">${error}</span><#t/>
    </td><#lt/>
</tr>
</#list>
</#if>
</#if>
<#if !attributes.labelPosition?? && (attributes.form.labelPosition)??>
<#assign labelPos = attributes.form.labelPosition/>
<#elseif attributes.labelPosition??>
<#assign labelPos = attributes.labelPosition/>
</#if>
<#--
	if the label position is top,
	then give the label it's own row in the table
-->
<tr>
<#if (labelPos!"") == 'top'>
    <td class="tdLabelTop" colspan="2"><#rt/>
<#else>
    <td class="tdLabel"><#rt/>
</#if>
<#if attributes.label??>
    <label <#t/>
<#if attributes.id??>
        for="${attributes.id}" <#t/>
</#if>
<#if hasFieldErrors>
        class="errorLabel"<#t/>
<#else>
        class="label"<#t/>
</#if>
    ><#t/>
<#if (attributes.required!false) && ((attributes.requiredPosition!"right") != 'right')>
        <span class="required">*</span><#t/>
</#if>
${attributes.label}<#t/>
<#if (attributes.required!false) && ((attributes.requiredPosition!"right") == 'right')>
 <span class="required">*</span><#t/>
</#if>
${attributes.labelseparator!":"}<#t/>
<#include "/${attributes.templateDir}/${attributes.expandTheme}/tooltip.ftl" />
</label><#t/>
</#if>
    </td><#lt/>
<#-- add the extra row -->
<#if (labelPos!"") == 'top'>
</tr>
<tr>
</#if>
