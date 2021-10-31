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

import com.opensymphony.xwork2.ActionContext;

import org.apache.struts2.TestAction;
import org.apache.struts2.views.jsp.AbstractTagTest;
import org.apache.struts2.views.jsp.DateTag;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

/**
 * Unit test for {@link org.apache.struts2.components.Date}.
 *
 */
public class DateTagTest extends AbstractTagTest {

    private DateTag tag;

    public void testCustomFormat() throws Exception {
        String format = "yyyy/MM/dd hh:mm:ss";
        Date now = new Date();
        String formatted = new SimpleDateFormat(format).format(now);
        context.put("myDate", now);

        tag.setName("myDate");
        tag.setNice(false);
        tag.setFormat(format);
        tag.doStartTag();
        tag.doEndTag();
        assertEquals(formatted, writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPageContext(pageContext);
        assertFalse("Tag state after doEndTag() under default tag clear state is equal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testCustomFormat_clearTagStateSet() throws Exception {
        String format = "yyyy/MM/dd hh:mm:ss";
        Date now = new Date();
        String formatted = new SimpleDateFormat(format).format(now);
        context.put("myDate", now);

        tag.setPerformClearTagStateForTagPoolingServers(true);  // Explicitly request tag state clearing.
        tag.setName("myDate");
        tag.setNice(false);
        tag.setFormat(format);
        tag.doStartTag();
        setComponentTagClearTagState(tag, true);  // Ensure component tag state clearing is set true (to match tag).
        tag.doEndTag();
        assertEquals(formatted, writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPerformClearTagStateForTagPoolingServers(true);
        freshTag.setPageContext(pageContext);
        assertTrue("Tag state after doEndTag() and explicit tag state clearing is inequal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testCustomGlobalFormatFormat() throws Exception {
        String format = "yyyy/MM/dd hh:mm:ss";
        Date now = new Date();
        String formatted = new SimpleDateFormat(format).format(now);
        context.put("myDate", now);

        ((TestAction) action).setText(org.apache.struts2.components.Date.DATETAG_PROPERTY, format);

        tag.setName("myDate");
        tag.setNice(false);
        tag.doStartTag();
        tag.doEndTag();
        assertEquals(formatted, writer.toString());
    }

    public void testCustomFormatWithTimezone() throws Exception {
        String format = "yyyy/MM/dd hh:mm:ss";
        Date now = Calendar.getInstance(TimeZone.getTimeZone("GMT+1")).getTime();
        SimpleDateFormat sdf = new SimpleDateFormat(format);
        sdf.setTimeZone(TimeZone.getTimeZone("GMT+1"));
        String formatted = sdf.format(now);
        context.put("myDate", now);

        tag.setName("myDate");
        tag.setNice(false);
        tag.setFormat(format);
        tag.setTimezone("GMT+1");
        tag.doStartTag();
        setComponentTagClearTagState(tag, true);  // Ensure component tag state clearing is set true (to match tag).
        tag.doEndTag();
        assertEquals(formatted, writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPageContext(pageContext);
        assertFalse("Tag state after doEndTag() under default tag clear state is equal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testCustomFormatWithTimezone_clearTagStateSet() throws Exception {
        String format = "yyyy/MM/dd hh:mm:ss";
        Date now = Calendar.getInstance(TimeZone.getTimeZone("GMT+1")).getTime();
        SimpleDateFormat sdf = new SimpleDateFormat(format);
        sdf.setTimeZone(TimeZone.getTimeZone("GMT+1"));
        String formatted = sdf.format(now);
        context.put("myDate", now);

        tag.setPerformClearTagStateForTagPoolingServers(true);  // Explicitly request tag state clearing.
        tag.setName("myDate");
        tag.setNice(false);
        tag.setFormat(format);
        tag.setTimezone("GMT+1");
        tag.doStartTag();
        setComponentTagClearTagState(tag, true);  // Ensure component tag state clearing is set true (to match tag).
        tag.doEndTag();
        assertEquals(formatted, writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPerformClearTagStateForTagPoolingServers(true);
        freshTag.setPageContext(pageContext);
        assertTrue("Tag state after doEndTag() and explicit tag state clearing is inequal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testCustomFormatWithTimezoneAsExpression() throws Exception {
        String format = "yyyy/MM/dd hh:mm:ss";
        Date now = Calendar.getInstance(TimeZone.getTimeZone("GMT+2")).getTime();
        SimpleDateFormat sdf = new SimpleDateFormat(format);
        sdf.setTimeZone(TimeZone.getTimeZone("GMT+2"));
        String formatted = sdf.format(now);
        context.put("myDate", now);
        context.put("myTimezone", "GMT+2");

        tag.setName("myDate");
        tag.setNice(false);
        tag.setFormat(format);
        tag.setTimezone("myTimezone");
        tag.doStartTag();
        tag.doEndTag();
        assertEquals(formatted, writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPageContext(pageContext);
        assertFalse("Tag state after doEndTag() under default tag clear state is equal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testCustomFormatWithTimezoneAsExpression_clearTagStateSet() throws Exception {
        String format = "yyyy/MM/dd hh:mm:ss";
        Date now = Calendar.getInstance(TimeZone.getTimeZone("GMT+2")).getTime();
        SimpleDateFormat sdf = new SimpleDateFormat(format);
        sdf.setTimeZone(TimeZone.getTimeZone("GMT+2"));
        String formatted = sdf.format(now);
        context.put("myDate", now);
        context.put("myTimezone", "GMT+2");

        tag.setPerformClearTagStateForTagPoolingServers(true);  // Explicitly request tag state clearing.
        tag.setName("myDate");
        tag.setNice(false);
        tag.setFormat(format);
        tag.setTimezone("myTimezone");
        tag.doStartTag();
        setComponentTagClearTagState(tag, true);  // Ensure component tag state clearing is set true (to match tag).
        tag.doEndTag();
        assertEquals(formatted, writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPerformClearTagStateForTagPoolingServers(true);
        freshTag.setPageContext(pageContext);
        assertTrue("Tag state after doEndTag() and explicit tag state clearing is inequal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testCustomFormatCalendar() throws Exception {
        String format = "yyyy/MM/dd hh:mm:ss";
        Calendar calendar = Calendar.getInstance();
        String formatted = new SimpleDateFormat(format).format(calendar.getTime());
        context.put("myDate", calendar);

        tag.setName("myDate");
        tag.setNice(false);
        tag.setFormat(format);
        tag.doStartTag();
        tag.doEndTag();
        assertEquals(formatted, writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPageContext(pageContext);
        assertFalse("Tag state after doEndTag() under default tag clear state is equal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testCustomFormatCalendar_clearTagStateSet() throws Exception {
        String format = "yyyy/MM/dd hh:mm:ss";
        Calendar calendar = Calendar.getInstance();
        String formatted = new SimpleDateFormat(format).format(calendar.getTime());
        context.put("myDate", calendar);

        tag.setPerformClearTagStateForTagPoolingServers(true);  // Explicitly request tag state clearing.
        tag.setName("myDate");
        tag.setNice(false);
        tag.setFormat(format);
        tag.doStartTag();
        setComponentTagClearTagState(tag, true);  // Ensure component tag state clearing is set true (to match tag).
        tag.doEndTag();
        assertEquals(formatted, writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPerformClearTagStateForTagPoolingServers(true);
        freshTag.setPageContext(pageContext);
        assertTrue("Tag state after doEndTag() and explicit tag state clearing is inequal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testCustomFormatLong() throws Exception {
        String format = "yyyy/MM/dd hh:mm:ss";
        Date date = new Date();
        String formatted = new SimpleDateFormat(format).format(date);
        // long
        context.put("myDate", date.getTime());

        tag.setName("myDate");
        tag.setNice(false);
        tag.setFormat(format);
        tag.doStartTag();
        tag.doEndTag();
        assertEquals(formatted, writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPageContext(pageContext);
        assertFalse("Tag state after doEndTag() under default tag clear state is equal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testCustomFormatLong_clearTagStateSet() throws Exception {
        String format = "yyyy/MM/dd hh:mm:ss";
        Date date = new Date();
        String formatted = new SimpleDateFormat(format).format(date);
        // long
        context.put("myDate", date.getTime());

        tag.setPerformClearTagStateForTagPoolingServers(true);  // Explicitly request tag state clearing.
        tag.setName("myDate");
        tag.setNice(false);
        tag.setFormat(format);
        tag.doStartTag();
        setComponentTagClearTagState(tag, true);  // Ensure component tag state clearing is set true (to match tag).
        tag.doEndTag();
        assertEquals(formatted, writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPerformClearTagStateForTagPoolingServers(true);
        freshTag.setPageContext(pageContext);
        assertTrue("Tag state after doEndTag() and explicit tag state clearing is inequal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testCustomFormatLocalDateTime() throws Exception {
        String format = "yyyy/MM/dd hh:mm:ss";
        LocalDateTime date = LocalDateTime.now();
        String formatted = date.format(DateTimeFormatter.ofPattern(format));
        context.put("myDate", date);

        tag.setName("myDate");
        tag.setNice(false);
        tag.setFormat(format);
        tag.doStartTag();
        tag.doEndTag();
        assertEquals(formatted, writer.toString());
    }

    public void testCustomFormatInstant() throws Exception {
        String format = "yyyy/MM/dd hh:mm:ss";
        Instant date = Instant.now();
        String formatted = DateTimeFormatter.ofPattern(format).format(date.atZone(ZoneId.systemDefault()));
        context.put("myDate", date);

        tag.setName("myDate");
        tag.setNice(false);
        tag.setFormat(format);
        tag.doStartTag();
        tag.doEndTag();
        assertEquals(formatted, writer.toString());
    }

    public void testDefaultFormat() throws Exception {
        Date now = new Date();
        String formatted = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.MEDIUM,
                ActionContext.getContext().getLocale()).format(now);

        context.put("myDate", now);
        tag.setName("myDate");
        tag.setNice(false);
        tag.doStartTag();
        tag.doEndTag();
        assertEquals(formatted, writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPageContext(pageContext);
        assertFalse("Tag state after doEndTag() under default tag clear state is equal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testDefaultFormat_clearTagStateSet() throws Exception {
        Date now = new Date();
        String formatted = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.MEDIUM,
                ActionContext.getContext().getLocale()).format(now);

        context.put("myDate", now);
        tag.setPerformClearTagStateForTagPoolingServers(true);  // Explicitly request tag state clearing.
        tag.setName("myDate");
        tag.setNice(false);
        tag.doStartTag();
        setComponentTagClearTagState(tag, true);  // Ensure component tag state clearing is set true (to match tag).
        tag.doEndTag();
        assertEquals(formatted, writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPerformClearTagStateForTagPoolingServers(true);
        freshTag.setPageContext(pageContext);
        assertTrue("Tag state after doEndTag() and explicit tag state clearing is inequal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testCustomFormatAndComponent() throws Exception {
        String format = "yyyy/MM/dd hh:mm:ss";
        Date now = new Date();
        String formatted = new SimpleDateFormat(format).format(now);
        context.put("myDate", now);

        tag.setName("myDate");
        tag.setFormat(format);
        tag.setNice(false);

        tag.doStartTag();

        // component test must be done between start and end tag
        org.apache.struts2.components.Date component = (org.apache.struts2.components.Date) tag.getComponent();
        assertEquals("myDate", component.getName());
        assertEquals(format, component.getFormat());
        assertEquals(false, component.isNice());

        tag.doEndTag();

        assertEquals(formatted, writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPageContext(pageContext);
        assertFalse("Tag state after doEndTag() under default tag clear state is equal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testCustomFormatAndComponent_clearTagStateSet() throws Exception {
        String format = "yyyy/MM/dd hh:mm:ss";
        Date now = new Date();
        String formatted = new SimpleDateFormat(format).format(now);
        context.put("myDate", now);

        tag.setPerformClearTagStateForTagPoolingServers(true);  // Explicitly request tag state clearing.
        tag.setName("myDate");
        tag.setFormat(format);
        tag.setNice(false);

        tag.doStartTag();
        setComponentTagClearTagState(tag, true);  // Ensure component tag state clearing is set true (to match tag).

        // component test must be done between start and end tag
        org.apache.struts2.components.Date component = (org.apache.struts2.components.Date) tag.getComponent();
        assertEquals("myDate", component.getName());
        assertEquals(format, component.getFormat());
        assertEquals(false, component.isNice());

        tag.doEndTag();

        assertEquals(formatted, writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPerformClearTagStateForTagPoolingServers(true);
        freshTag.setPageContext(pageContext);
        assertTrue("Tag state after doEndTag() and explicit tag state clearing is inequal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testSetId() throws Exception {
        String format = "yyyy/MM/dd hh:mm:ss";
        Date now = new Date();
        String formatted = new SimpleDateFormat(format).format(now);
        context.put("myDate", now);

        tag.setName("myDate");
        tag.setNice(false);
        tag.setFormat(format);
        tag.setVar("myId");
        tag.doStartTag();
        tag.doEndTag();
        assertEquals(formatted, context.get("myId"));

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPageContext(pageContext);
        assertFalse("Tag state after doEndTag() under default tag clear state is equal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testSetId_clearTagStateSet() throws Exception {
        String format = "yyyy/MM/dd hh:mm:ss";
        Date now = new Date();
        String formatted = new SimpleDateFormat(format).format(now);
        context.put("myDate", now);

        tag.setPerformClearTagStateForTagPoolingServers(true);  // Explicitly request tag state clearing.
        tag.setName("myDate");
        tag.setNice(false);
        tag.setFormat(format);
        tag.setVar("myId");
        tag.doStartTag();
        setComponentTagClearTagState(tag, true);  // Ensure component tag state clearing is set true (to match tag).
        tag.doEndTag();
        assertEquals(formatted, context.get("myId"));

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPerformClearTagStateForTagPoolingServers(true);
        freshTag.setPageContext(pageContext);
        assertTrue("Tag state after doEndTag() and explicit tag state clearing is inequal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testFutureNiceHour() throws Exception {
        Date now = new Date();
        Calendar future = Calendar.getInstance();
        future.setTime(now);
        future.add(Calendar.HOUR, 1);
        future.add(Calendar.SECOND, 5); // always add a little slack otherwise we could calculate wrong

        context.put("myDate", future.getTime());
        tag.setName("myDate");
        tag.setNice(true);
        tag.doStartTag();
        tag.doEndTag();
        assertEquals("in one hour", writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPageContext(pageContext);
        assertFalse("Tag state after doEndTag() under default tag clear state is equal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testFutureNiceHour_clearTagStateSet() throws Exception {
        Date now = new Date();
        Calendar future = Calendar.getInstance();
        future.setTime(now);
        future.add(Calendar.HOUR, 1);
        future.add(Calendar.SECOND, 5); // always add a little slack otherwise we could calculate wrong

        context.put("myDate", future.getTime());
        tag.setPerformClearTagStateForTagPoolingServers(true);  // Explicitly request tag state clearing.
        tag.setName("myDate");
        tag.setNice(true);
        tag.doStartTag();
        setComponentTagClearTagState(tag, true);  // Ensure component tag state clearing is set true (to match tag).
        tag.doEndTag();
        assertEquals("in one hour", writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPerformClearTagStateForTagPoolingServers(true);
        freshTag.setPageContext(pageContext);
        assertTrue("Tag state after doEndTag() and explicit tag state clearing is inequal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testPastNiceHour() throws Exception {
        Date now = new Date();
        Calendar future = Calendar.getInstance();
        future.setTime(now);
        future.add(Calendar.HOUR, -1);
        future.add(Calendar.SECOND, -5); // always add a little slack otherwise we could calculate wrong

        context.put("myDate", future.getTime());
        tag.setName("myDate");
        tag.setNice(true);
        tag.doStartTag();
        tag.doEndTag();
        assertEquals("one hour ago", writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPageContext(pageContext);
        assertFalse("Tag state after doEndTag() under default tag clear state is equal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testPastNiceHour_clearTagStateSet() throws Exception {
        Date now = new Date();
        Calendar future = Calendar.getInstance();
        future.setTime(now);
        future.add(Calendar.HOUR, -1);
        future.add(Calendar.SECOND, -5); // always add a little slack otherwise we could calculate wrong

        context.put("myDate", future.getTime());
        tag.setPerformClearTagStateForTagPoolingServers(true);  // Explicitly request tag state clearing.
        tag.setName("myDate");
        tag.setNice(true);
        tag.doStartTag();
        setComponentTagClearTagState(tag, true);  // Ensure component tag state clearing is set true (to match tag).
        tag.doEndTag();
        assertEquals("one hour ago", writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPerformClearTagStateForTagPoolingServers(true);
        freshTag.setPageContext(pageContext);
        assertTrue("Tag state after doEndTag() and explicit tag state clearing is inequal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testFutureNiceHourMinSec() throws Exception {
        Date now = new Date();
        Calendar future = Calendar.getInstance();
        future.setTime(now);
        future.add(Calendar.HOUR, 2);
        future.add(Calendar.MINUTE, 33);
        future.add(Calendar.SECOND, 5); // always add a little slack otherwise we could calculate wrong

        context.put("myDate", future.getTime());
        tag.setName("myDate");
        tag.setNice(true);
        tag.doStartTag();
        tag.doEndTag();
        assertEquals("in 2 hours, 33 minutes", writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPageContext(pageContext);
        assertFalse("Tag state after doEndTag() under default tag clear state is equal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testFutureNiceHourMinSec_clearTagStateSet() throws Exception {
        Date now = new Date();
        Calendar future = Calendar.getInstance();
        future.setTime(now);
        future.add(Calendar.HOUR, 2);
        future.add(Calendar.MINUTE, 33);
        future.add(Calendar.SECOND, 5); // always add a little slack otherwise we could calculate wrong

        context.put("myDate", future.getTime());
        tag.setPerformClearTagStateForTagPoolingServers(true);  // Explicitly request tag state clearing.
        tag.setName("myDate");
        tag.setNice(true);
        tag.doStartTag();
        setComponentTagClearTagState(tag, true);  // Ensure component tag state clearing is set true (to match tag).
        tag.doEndTag();
        assertEquals("in 2 hours, 33 minutes", writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPerformClearTagStateForTagPoolingServers(true);
        freshTag.setPageContext(pageContext);
        assertTrue("Tag state after doEndTag() and explicit tag state clearing is inequal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testPastNiceHourMin() throws Exception {
        Date now = new Date();
        Calendar past = Calendar.getInstance();
        past.setTime(now);
        past.add(Calendar.HOUR, -4);
        past.add(Calendar.MINUTE, -55);
        past.add(Calendar.SECOND, -5); // always add a little slack otherwise we could calculate wrong

        context.put("myDate", past.getTime());
        tag.setName("myDate");
        tag.setNice(true);
        tag.doStartTag();
        tag.doEndTag();
        assertEquals("4 hours, 55 minutes ago", writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPageContext(pageContext);
        assertFalse("Tag state after doEndTag() under default tag clear state is equal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testPastNiceHourMin_clearTagStateSet() throws Exception {
        Date now = new Date();
        Calendar past = Calendar.getInstance();
        past.setTime(now);
        past.add(Calendar.HOUR, -4);
        past.add(Calendar.MINUTE, -55);
        past.add(Calendar.SECOND, -5); // always add a little slack otherwise we could calculate wrong

        context.put("myDate", past.getTime());
        tag.setPerformClearTagStateForTagPoolingServers(true);  // Explicitly request tag state clearing.
        tag.setName("myDate");
        tag.setNice(true);
        tag.doStartTag();
        setComponentTagClearTagState(tag, true);  // Ensure component tag state clearing is set true (to match tag).
        tag.doEndTag();
        assertEquals("4 hours, 55 minutes ago", writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPerformClearTagStateForTagPoolingServers(true);
        freshTag.setPageContext(pageContext);
        assertTrue("Tag state after doEndTag() and explicit tag state clearing is inequal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testFutureLessOneMin() throws Exception {
        Date now = new Date();
        Calendar future = Calendar.getInstance();
        future.setTime(now);
        future.add(Calendar.SECOND, 47);
        future.add(Calendar.SECOND, 5); // always add a little slack otherwise we could calculate wrong

        context.put("myDate", future.getTime());
        tag.setName("myDate");
        tag.setNice(true);
        tag.doStartTag();
        tag.doEndTag();
        assertEquals("in an instant", writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPageContext(pageContext);
        assertFalse("Tag state after doEndTag() under default tag clear state is equal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testFutureLessOneMin_clearTagStateSet() throws Exception {
        Date now = new Date();
        Calendar future = Calendar.getInstance();
        future.setTime(now);
        future.add(Calendar.SECOND, 47);
        future.add(Calendar.SECOND, 5); // always add a little slack otherwise we could calculate wrong

        context.put("myDate", future.getTime());
        tag.setPerformClearTagStateForTagPoolingServers(true);  // Explicitly request tag state clearing.
        tag.setName("myDate");
        tag.setNice(true);
        tag.doStartTag();
        setComponentTagClearTagState(tag, true);  // Ensure component tag state clearing is set true (to match tag).
        tag.doEndTag();
        assertEquals("in an instant", writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPerformClearTagStateForTagPoolingServers(true);
        freshTag.setPageContext(pageContext);
        assertTrue("Tag state after doEndTag() and explicit tag state clearing is inequal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testFutureLessOneHour() throws Exception {
        Date now = new Date();
        Calendar future = Calendar.getInstance();
        future.setTime(now);
        future.add(Calendar.MINUTE, 36);
        future.add(Calendar.SECOND, 5); // always add a little slack otherwise we could calculate wrong

        context.put("myDate", future.getTime());
        tag.setName("myDate");
        tag.setNice(true);
        tag.doStartTag();
        tag.doEndTag();
        assertEquals("in 36 minutes", writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPageContext(pageContext);
        assertFalse("Tag state after doEndTag() under default tag clear state is equal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testFutureLessOneHour_clearTagStateSet() throws Exception {
        Date now = new Date();
        Calendar future = Calendar.getInstance();
        future.setTime(now);
        future.add(Calendar.MINUTE, 36);
        future.add(Calendar.SECOND, 5); // always add a little slack otherwise we could calculate wrong

        context.put("myDate", future.getTime());
        tag.setPerformClearTagStateForTagPoolingServers(true);  // Explicitly request tag state clearing.
        tag.setName("myDate");
        tag.setNice(true);
        tag.doStartTag();
        setComponentTagClearTagState(tag, true);  // Ensure component tag state clearing is set true (to match tag).
        tag.doEndTag();
        assertEquals("in 36 minutes", writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPerformClearTagStateForTagPoolingServers(true);
        freshTag.setPageContext(pageContext);
        assertTrue("Tag state after doEndTag() and explicit tag state clearing is inequal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testFutureLessOneYear() throws Exception {
        Date now = new Date();
        Calendar future = Calendar.getInstance();
        future.setTime(now);
        future.add(Calendar.HOUR, 40 * 24);
        future.add(Calendar.SECOND, 5); // always add a little slack otherwise we could calculate wrong

        context.put("myDate", future.getTime());
        tag.setName("myDate");
        tag.setNice(true);
        tag.doStartTag();
        tag.doEndTag();
        assertEquals("in 40 days", writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPageContext(pageContext);
        assertFalse("Tag state after doEndTag() under default tag clear state is equal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testFutureLessOneYear_clearTagStateSet() throws Exception {
        Date now = new Date();
        Calendar future = Calendar.getInstance();
        future.setTime(now);
        future.add(Calendar.HOUR, 40 * 24);
        future.add(Calendar.SECOND, 5); // always add a little slack otherwise we could calculate wrong

        context.put("myDate", future.getTime());
        tag.setPerformClearTagStateForTagPoolingServers(true);  // Explicitly request tag state clearing.
        tag.setName("myDate");
        tag.setNice(true);
        tag.doStartTag();
        setComponentTagClearTagState(tag, true);  // Ensure component tag state clearing is set true (to match tag).
        tag.doEndTag();
        assertEquals("in 40 days", writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPerformClearTagStateForTagPoolingServers(true);
        freshTag.setPageContext(pageContext);
        assertTrue("Tag state after doEndTag() and explicit tag state clearing is inequal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testFutureTwoYears() throws Exception {
        Date now = new Date();
        Calendar future = Calendar.getInstance();
        future.setTime(now);
        future.add(Calendar.YEAR, 2);
        future.add(Calendar.DATE, 1);
        future.add(Calendar.SECOND, 5); // always add a little slack otherwise we could calculate wrong

        context.put("myDate", future.getTime());
        tag.setName("myDate");
        tag.setNice(true);
        tag.doStartTag();
        tag.doEndTag();

        // hmmm the Date component isn't the best to calculate the excat difference so we'll just check
        // that it starts with in 2 years
        assertTrue(writer.toString().startsWith("in 2 years"));

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPageContext(pageContext);
        assertFalse("Tag state after doEndTag() under default tag clear state is equal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testFutureTwoYears_clearTagStateSet() throws Exception {
        Date now = new Date();
        Calendar future = Calendar.getInstance();
        future.setTime(now);
        future.add(Calendar.YEAR, 2);
        future.add(Calendar.DATE, 1);
        future.add(Calendar.SECOND, 5); // always add a little slack otherwise we could calculate wrong

        context.put("myDate", future.getTime());
        tag.setPerformClearTagStateForTagPoolingServers(true);  // Explicitly request tag state clearing.
        tag.setName("myDate");
        tag.setNice(true);
        tag.doStartTag();
        setComponentTagClearTagState(tag, true);  // Ensure component tag state clearing is set true (to match tag).
        tag.doEndTag();

        // hmmm the Date component isn't the best to calculate the excat difference so we'll just check
        // that it starts with in 2 years
        assertTrue(writer.toString().startsWith("in 2 years"));

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPerformClearTagStateForTagPoolingServers(true);
        freshTag.setPageContext(pageContext);
        assertTrue("Tag state after doEndTag() and explicit tag state clearing is inequal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testNoDateObjectInContext() throws Exception {
        context.put("myDate", "this is not a java.util.Date object");
        tag.setName("myDate");
        tag.setNice(true);
        tag.doStartTag();
        tag.doEndTag();
        //should return a blank
        assertEquals("", writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPageContext(pageContext);
        assertFalse("Tag state after doEndTag() under default tag clear state is equal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    public void testNoDateObjectInContext_clearTagStateSet() throws Exception {
        context.put("myDate", "this is not a java.util.Date object");
        tag.setPerformClearTagStateForTagPoolingServers(true);  // Explicitly request tag state clearing.
        tag.setName("myDate");
        tag.setNice(true);
        tag.doStartTag();
        setComponentTagClearTagState(tag, true);  // Ensure component tag state clearing is set true (to match tag).
        tag.doEndTag();
        //should return a blank
        assertEquals("", writer.toString());

        // Basic sanity check of clearTagStateForTagPoolingServers() behaviour for Struts Tags after doEndTag().
        DateTag freshTag = new DateTag();
        freshTag.setPerformClearTagStateForTagPoolingServers(true);
        freshTag.setPageContext(pageContext);
        assertTrue("Tag state after doEndTag() and explicit tag state clearing is inequal to new Tag with pageContext/parent set.  " +
                "May indicate that clearTagStateForTagPoolingServers() calls are not working properly.",
                strutsBodyTagsAreReflectionEqual(tag, freshTag));
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        tag = new DateTag();
        tag.setPageContext(pageContext);
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        tag = null;
    }

}
