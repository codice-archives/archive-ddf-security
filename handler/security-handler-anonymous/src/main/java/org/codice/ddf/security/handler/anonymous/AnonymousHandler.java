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
package org.codice.ddf.security.handler.anonymous;

import org.codice.ddf.security.handler.api.AuthenticationHandler;
import org.codice.ddf.security.handler.api.BaseAuthenticationToken;
import org.codice.ddf.security.handler.api.HandlerResult;
import org.codice.ddf.security.handler.api.UPAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * Handler that allows anonymous user access via a guest user account. The guest/guest account
 * must be present in the user store for this handler to work correctly.
 */
public class AnonymousHandler implements AuthenticationHandler {
    public static final Logger logger = LoggerFactory.getLogger(AnonymousHandler.class.getName());

    /**
     * Anonymous type to use when configuring context policy.
     */
    public static final String AUTH_TYPE = "ANON";

    protected static final String GUEST_USER = "guest";

    protected static final String GUEST_PW = "guest";

    @Override
    public String getAuthenticationType() {
        return AUTH_TYPE;
    }

    @Override
    public HandlerResult getNormalizedToken(ServletRequest request, ServletResponse response, FilterChain chain, boolean resolve) {
        HandlerResult result = new HandlerResult();

        // For anonymous - always generate authentication credentials as 'guest' in the default realm
        UPAuthenticationToken usernameToken = new UPAuthenticationToken(GUEST_USER, GUEST_PW);

        result.setSource(BaseAuthenticationToken.DEFAULT_REALM + "-AnonymousHandler");
        result.setStatus(HandlerResult.Status.COMPLETED);
        result.setToken(usernameToken);
        return result;
    }

    @Override
    public HandlerResult handleError(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws ServletException {
        HandlerResult result = new HandlerResult();
        result.setSource(BaseAuthenticationToken.DEFAULT_REALM + "-AnonymousHandler");
        logger.debug("In error handler for anonymous - returning no action taken.");
        result.setStatus(HandlerResult.Status.NO_ACTION);
        return result;
    }
}
