/**
 * Copyright (c) Codice Foundation
 * 
 * This is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser
 * General Public License as published by the Free Software Foundation, either version 3 of the
 * License, or any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details. A copy of the GNU Lesser General Public License
 * is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 * 
 **/
package ddf.security.pep.interceptor;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;

import org.apache.cxf.binding.soap.model.SoapOperationInfo;
import org.apache.cxf.interceptor.security.AccessDeniedException;
import org.apache.cxf.message.Message;
import org.codice.ddf.security.handler.api.AnonymousAuthenticationToken;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import ddf.security.common.audit.SecurityLogger;
import ddf.security.service.SecurityManager;
import ddf.security.service.impl.SecurityAssertionStore;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ SecurityAssertionStore.class, SecurityLogger.class })
public class TestPepInterceptorNullAssertion {

    @Rule
    private ExpectedException expectedExForNullMessage = ExpectedException.none();

    @Test
    public void testMessageNullSecurityAssertion() throws Exception {
        PEPAuthorizingInterceptor interceptor = new PEPAuthorizingInterceptor();
        SecurityManager mockSecurityManager = mock(SecurityManager.class);
        interceptor.setSecurityManager(mockSecurityManager);
        interceptor.setAlwaysDenyAnonymousAccess(false);

        Message messageWithNullSecurityAssertion = mock(Message.class);
        
        
        PowerMockito.mockStatic(SoapOperationInfo.class);
        PowerMockito.mockStatic(SecurityAssertionStore.class);
        PowerMockito.mockStatic(SecurityLogger.class);

        try {
            interceptor.handleMessage(messageWithNullSecurityAssertion);
            Assert.fail();
        } catch (AccessDeniedException e) {
        }

        Mockito.verify(mockSecurityManager).getSubject(
                Matchers.isA(AnonymousAuthenticationToken.class));

        PowerMockito.verifyStatic();
    }

    @Test
    public void testDenyAnonymousAccess() throws Exception {
        PEPAuthorizingInterceptor interceptor = new PEPAuthorizingInterceptor();
        SecurityManager mockSecurityManager = mock(SecurityManager.class);
        interceptor.setSecurityManager(mockSecurityManager);
        interceptor.setAlwaysDenyAnonymousAccess(true);

        Message messageWithNullSecurityAssertion = mock(Message.class);

        PowerMockito.mockStatic(SoapOperationInfo.class);
        PowerMockito.mockStatic(SecurityAssertionStore.class);
        PowerMockito.mockStatic(SecurityLogger.class);

        try {
            interceptor.handleMessage(messageWithNullSecurityAssertion);
            Assert.fail();
        } catch (AccessDeniedException e) {
        }

        Mockito.verify(mockSecurityManager, never()).getSubject(Mockito.anyObject());

        PowerMockito.verifyStatic();
    }
}
