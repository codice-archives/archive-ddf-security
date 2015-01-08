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
package org.codice.ddf.security.interceptor.saml;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPMessage;

import org.apache.commons.lang.StringUtils;
import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.saaj.SAAJInInterceptor;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.phase.Phase;
import org.apache.cxf.ws.security.wss4j.AbstractWSS4JInterceptor;
import org.apache.cxf.ws.security.wss4j.WSS4JInInterceptor;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * Interceptor that performs advanced SAML Validation that isn't covered by
 * WSS4j classes. The validation by this class is only performed if the
 * Assertion is a SAML 2.0 Assertion and if the Assertion is present, otherwise
 * this class will not do any validation
 * 
 * In general for all time checks a 1 minute fudge factor is given
 * 
 * The validation that is performed is:
 * <ul>
 * <li>Check that the SAML Version Attribute is 1.0, 1.1 or 2.0
 * <li>Ensure the Assertion\@ID attribute is populated
 * <li>Ensure the Assertion\AuthNStatement is present
 * <li>Ensure the Assertion\AuthnStatement\\@AuthnInstant is before the current
 * time
 * <li>Ensure the Assertion\AuthnStatement\AuthnContext\AuthnContextDeclRef
 * value is present and a valid value as specified in the SAML 2.0 Spec
 * <li>Ensure the Assertion\AuthnStatement\@SessionNotOnOrAfter time is valid
 * compared to the current time
 * <li>Ensure the Assertion\@IssueInstant time is before the current time
 * <li>Ensure the Assertion\Issuer\@Format value is present and a valid value as
 * specified in the SAML 2.0 spec
 * <li>Ensure the Assertion\Subject\SubjectConfirmation is present
 * <li>Ensure the Assertion\Subject\SubjectConfirmation\@Method is present and a
 * valid value
 * <li>Ensure the Assertion\Subject\SubjectConfirmation\SubjectConfirmationData @NotBefore
 * and @NotOnOrAfter dates are valid when compared to the current datetime
 * <li>Ensure the Assertion\Subject\NameID\@Format is present a valid value per
 * the SAML 2.0 spec
 * <li>Ensure the Assertion\Conditions @NotOnOrAfter and @NotBefore values are
 * present and valid compared to the current datetime.
 *
 */
public class EnhancedSamlValidatorInterceptor extends AbstractWSS4JInterceptor {

    private Logger LOGGER = LoggerFactory.getLogger(EnhancedSamlValidatorInterceptor.class);

    private static final String ASSERTION_ELEMENT_NAME = "Assertion";

    private static final String VERSION_ELEMENT_NAME = "Version";

    private static final String DECL_REF_PREFIX = "urn:oasis:names:tc:SAML:2.0:ac:classes";

    private static final int OFFSET_TIME_CHECK_MINUTES = 1;

    private static final Set<String> SAML_VERSIONS = new HashSet<String>();
    static {
        SAML_VERSIONS.add("1.0");
        SAML_VERSIONS.add("1.1");
        SAML_VERSIONS.add("2.0");
    }

    private static final Set<String> ALLOWED_FORMATS = new HashSet<String>();
    static {
        ALLOWED_FORMATS.add("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
        ALLOWED_FORMATS.add("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        ALLOWED_FORMATS.add("urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName");
        ALLOWED_FORMATS.add("urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName");
        ALLOWED_FORMATS.add("urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos");
        ALLOWED_FORMATS.add("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");
        ALLOWED_FORMATS.add("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
        ALLOWED_FORMATS.add("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
    }

    private static final Set<String> CONFIRMATION_METHODS = new HashSet<String>();
    static {
        CONFIRMATION_METHODS.add("urn:oasis:names:tc:SAML:1.0:cm:bearer");
        CONFIRMATION_METHODS.add("urn:oasis:names:tc:SAML:1.1:cm:bearer");
        CONFIRMATION_METHODS.add("urn:oasis:names:tc:SAML:2.0:cm:bearer");
        CONFIRMATION_METHODS.add("urn:oasis:names:tc:SAML:1.0:cm:sender-vouches");
        CONFIRMATION_METHODS.add("urn:oasis:names:tc:SAML:1.1:cm:sender-vouches");
        CONFIRMATION_METHODS.add("urn:oasis:names:tc:SAML:2.0:cm:sender-vouches");
        CONFIRMATION_METHODS.add("urn:oasis:names:tc:SAML:1.0:cm:holder-of-key");
        CONFIRMATION_METHODS.add("urn:oasis:names:tc:SAML:1.1:cm:holder-of-key");
        CONFIRMATION_METHODS.add("urn:oasis:names:tc:SAML:2.0:cm:holder-of-key");
    }

    public EnhancedSamlValidatorInterceptor() {
        super();
        setPhase(Phase.PRE_PROTOCOL);
        // make sure this interceptor runs before the WSS4J one in the same
        // Phase, otherwise it won't work

        Set<String> before = getBefore();
        before.add(WSS4JInInterceptor.class.getName());
        LOGGER.debug("Creating a new instance of the EnhancedSamlValidatorInterceptor which provides enhanced SAML validation for SOAP Web Services");
    }

    /**
     * Intercepts a message. Interceptors should NOT invoke handleMessage or
     * handleFault on the next interceptor - the interceptor chain will take
     * care of this.
     *
     * @param message
     */
    @Override
    public void handleMessage(SoapMessage message) throws Fault {

        SOAPMessage soapMessage = getSOAPMessage(message);

        try {
            SOAPHeader header = soapMessage.getSOAPHeader();
            if (header != null) {
                NodeList list = header.getElementsByTagNameNS("*", ASSERTION_ELEMENT_NAME);

                if (list != null && list.getLength() > 0) {
                    // check the SAML Version number to ensure it is valid
                    Element assertionElement = (Element) list.item(0);
                    String version = assertionElement.getAttribute(VERSION_ELEMENT_NAME);
                    if (!SAML_VERSIONS.contains(version)) {
                        throw new WSSecurityException(
                                "The Assertion\\@Version attribute must be a valid SAML Assertion value: "
                                        + SAML_VERSIONS);
                    }

                    AssertionWrapper assertion = new AssertionWrapper(assertionElement);

                    // Check the SAML Assertion @ID Attribute
                    String id = assertion.getId();
                    if (StringUtils.isBlank(id)) {
                        throw new WSSecurityException(
                                "The Assertion\\@ID MUST be populated with a valid ID");
                    }

                    Assertion saml2Assertion = assertion.getSaml2();
                    if (saml2Assertion != null) {
                        validateSaml2Assertion(saml2Assertion);
                    } else {
                        LOGGER.debug(
                                "Not performing enhanced SAML 2.0 Validation since SAML Assertion was version {}",
                                version);
                    }
                }
            } else {
                LOGGER.debug("SOAP Header not present, so not performing SAML Validation");
            }
        } catch (WSSecurityException e) {
            LOGGER.warn("SAML Validation failed: " + e.getMessage());
            throw new Fault(e);
        } catch (SOAPException e) {
            LOGGER.warn("Exception encountered when trying to parse SOAPHeader from SOAPMessage: "
                    + e.getMessage());
            throw new Fault(e);
        }

    }

    /**
     * Checks the SAML Assertion and enforces the enhanced validation rules
     * 
     * @param saml2Assertion
     *            the assertion
     * @throws WSSecurityException
     *             if a validated error occurs
     */
    protected void validateSaml2Assertion(Assertion saml2Assertion) throws WSSecurityException {
        DateTime now = new DateTime();

        // Check to ensure that there is an AuthNStatement included in the
        // Assertion
        List<AuthnStatement> authnStatementList = saml2Assertion.getAuthnStatements();
        if (authnStatementList == null || authnStatementList.isEmpty()) {
            throw new WSSecurityException("The Assertion\\AuthnStatement element is not present.");
        }

        // Check to make sure the AuthInstant is after the current time
        // (subtract one minute from current time
        // to account for slight time differences
        AuthnStatement authNStatment = authnStatementList.get(0);
        DateTime dateTime = authNStatment.getAuthnInstant();
        if (dateTime == null || now.isBefore(dateTime.minusMinutes(OFFSET_TIME_CHECK_MINUTES))) {
            throw new WSSecurityException(
                    "The Assertion\\AuthnStatement\\@AuthnInstant MUST NOT be after the current time.");
        }

        AuthnContext authnContext = authNStatment.getAuthnContext();
        if (authnContext == null || authnContext.getAuthnContextDeclRef() == null) {
            throw new WSSecurityException(
                    "The Assertion\\AuthnStatement\\AuthnContext\\AuthnContextDeclRef value is is missing.");
        } else {
            String declRef = authnContext.getAuthnContextDeclRef().getAuthnContextDeclRef();
            if (declRef == null || !declRef.startsWith(DECL_REF_PREFIX)) {
                throw new WSSecurityException(
                        "The Assertion\\AuthnStatement\\AuthnContext\\AuthnContextDeclRef value "
                                + "is not a value as specified by the SAML Authentication Context specification.");
            }
        }

        dateTime = authNStatment.getSessionNotOnOrAfter();
        if (dateTime == null || now.isAfter(dateTime.plusMinutes(OFFSET_TIME_CHECK_MINUTES))) {
            throw new WSSecurityException(
                    "The Assertion\\AuthnStatement\\@SessionNotOnOrAfter value MUST NOT be before the current time");
        }

        dateTime = saml2Assertion.getIssueInstant();
        if (dateTime == null || now.isBefore(dateTime.minusMinutes(OFFSET_TIME_CHECK_MINUTES))) {
            throw new WSSecurityException(
                    "The Assertion\\@IssueInstant value MUST NOT be after the current time.");
        }

        Issuer issuer = saml2Assertion.getIssuer();
        if (issuer == null) {
            throw new WSSecurityException(
                    "The Assertion\\Issuer\\@Format attribute MUST contain a valid value per the allowed values: "
                            + ALLOWED_FORMATS);
        } else {
            String format = issuer.getFormat();
            if (StringUtils.isBlank(format) || !ALLOWED_FORMATS.contains(format)) {
                throw new WSSecurityException(
                        "The Assertion\\Issuer\\@Format attribute MUST contain a valid value per the allowed values: "
                                + ALLOWED_FORMATS);
            }
        }

        Subject subject = saml2Assertion.getSubject();
        if (subject == null) {
            throw new WSSecurityException(
                    "The Assertion\\Subject\\SubjectConfirmation element is not present.");
        } else {
            List<SubjectConfirmation> confirmations = subject.getSubjectConfirmations();
            if (confirmations == null || confirmations.isEmpty()) {
                throw new WSSecurityException(
                        "The Assertion\\Subject\\SubjectConfirmation element is not present.");
            } else {
                SubjectConfirmation subjectConf = confirmations.get(0);
                String confMethod = subjectConf.getMethod();
                if (confMethod == null || !CONFIRMATION_METHODS.contains(confMethod)) {
                    throw new WSSecurityException(
                            "The Assertion\\Subject\\SubjectConfirmation\\@Method attribute is not a valid value as defined in the SAML Spec: "
                                    + CONFIRMATION_METHODS);
                }
                SubjectConfirmationData subjectConfData = subjectConf.getSubjectConfirmationData();
                if (subjectConfData == null) {
                    throw new WSSecurityException(
                            "The Assertion\\Subject\\SubjectConfirmation\\SubjectConfirmationData must exist");
                }
                dateTime = subjectConfData.getNotBefore();
                if (dateTime == null
                        || now.isBefore(dateTime.minusMinutes(OFFSET_TIME_CHECK_MINUTES))) {
                    throw new WSSecurityException(
                            "The Assertion\\Subject\\SubjectConfirmation\\SubjectConfirmationData\\@NotBefore value MUST NOT be before the current time");
                }

                dateTime = saml2Assertion.getSubject().getSubjectConfirmations().get(0)
                        .getSubjectConfirmationData().getNotOnOrAfter();
                if (dateTime == null
                        || now.isAfter(dateTime.plusMinutes(OFFSET_TIME_CHECK_MINUTES))) {
                    throw new WSSecurityException(
                            "The Assertion\\Subject\\SubjectConfirmation\\SubjectConfirmationData\\@NotOnOrAfter value MUST NOT ve after the current time");
                }
            }

            if (subject.getNameID() == null || subject.getNameID().getFormat() == null) {
                throw new WSSecurityException(
                        "The Assertion\\Subject\\NameID\\@Format must be populated with a valid value");
            } else if (!ALLOWED_FORMATS.contains(subject.getNameID().getFormat())) {
                throw new WSSecurityException(
                        "The Assertion\\Subject\\NameID\\@Format attribute is invalid, allowed values are: "
                                + ALLOWED_FORMATS);
            }
        }

        Conditions conditions = saml2Assertion.getConditions();
        if (conditions == null) {
            throw new WSSecurityException("The Assertion\\Conditions element MUST BE present.");
        } else {
            dateTime = conditions.getNotOnOrAfter();
            if (dateTime == null || now.isAfter(dateTime.plusMinutes(OFFSET_TIME_CHECK_MINUTES))) {
                throw new WSSecurityException(
                        "The current Date cannot be after the Assertion\\Conditions\\@NotOnOrAfter value");
            }

            dateTime = conditions.getNotBefore();
            if (dateTime == null || now.isBefore(dateTime.minusMinutes(OFFSET_TIME_CHECK_MINUTES))) {
                throw new WSSecurityException(
                        "The current Date cannot be before the Assertion\\Conditions\\@NotBefore value");
            }
        }
    }

    private SOAPMessage getSOAPMessage(SoapMessage msg) {
        SAAJInInterceptor.INSTANCE.handleMessage(msg);
        return msg.getContent(SOAPMessage.class);
    }

}
