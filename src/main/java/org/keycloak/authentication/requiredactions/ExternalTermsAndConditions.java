
/*
    Based on official Keycloak repository TermsAndConditions.java
*/

/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package org.keycloak.authentication.requiredactions;

import org.keycloak.Config;
import org.keycloak.authentication.*;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.DefaultRequiredActions;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.authentication.requiredactions.DeleteAccount;

import org.jboss.logging.Logger;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author <a href="mailto:etinquis@gmail.com">Martyn York</a>
 * @version $Revision: 1 $
 */
public class ExternalTermsAndConditions implements RequiredActionProvider, RequiredActionFactory {
    public static final String PROVIDER_ID = "EXTERNAL_TERMS_AND_CONDITIONS";
    public static final String USER_TERMS_ATTRIBUTE = "agreed_tos";
    public static final String USER_PRIVACY_ATTRIBUTE = "agreed_privacy";

    public static final String FORM_TOS_URL_ATTRIBUTE = "tos_url";
    public static final String FORM_PRIVACY_URL_ATTRIBUTE = "privacy_url";

    // https://mysite.com/policy/latest.json
    private static final String LATEST_POLICIES_URL = "EXTERNALTERMSANDCONDITIONS_LATEST_TERMS_URL";
    // https://mysite.com/policy/%1$s/%1$s.%2$s.html (where %1$s is the policy type [tos, privacy] and %2$s is the latest value)
    private static final String POLICIES_BASE_URL = "EXTERNALTERMSANDCONDITIONS_POLICIES_BASE_URL";

    private static final Logger LOGGER = Logger.getLogger(ExternalTermsAndConditions.class);

    private String latestPoliciesUrl;
    private String policiesBaseUrl;

    private String latestTOS;
    private String latestPrivacy;

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {
        LOGGER.debug("Initializing ExternalTermsAndConditions Required Action");

        latestPoliciesUrl = System.getenv(LATEST_POLICIES_URL);
        if (latestPoliciesUrl == null) {
            latestPoliciesUrl = System.getProperties().getProperty(LATEST_POLICIES_URL);
        }

        policiesBaseUrl = System.getenv(POLICIES_BASE_URL);
        if (policiesBaseUrl == null) {
            policiesBaseUrl = System.getProperties().getProperty(POLICIES_BASE_URL);
        }

        if (latestPoliciesUrl == null || policiesBaseUrl == null) {
            LOGGER.error("Missing required configuration");
            throw new RuntimeException("Missing required configuration");
        }
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    private static Map FetchLatestPolicies(HttpClientProvider httpProvider, String policiesUrl) throws IOException {
        CloseableHttpClient httpClient = httpProvider.getHttpClient();
        HttpGet httpGet = new HttpGet(policiesUrl);
        httpGet.setHeader("Pragma", "no-cache");
        httpGet.setHeader("Cache-Control", "no-cache, no-store");
        httpGet.setHeader("Accept", "application/json");

        try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
            try {
                InputStream content = response.getEntity().getContent();
                
                return new ObjectMapper().readValue(content, Map.class);
            } finally {
                EntityUtils.consumeQuietly(response.getEntity());
            }
        }
    }

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        try {
            Map metadata = FetchLatestPolicies(context.getSession().getProvider(HttpClientProvider.class), latestPoliciesUrl);
            latestTOS = metadata.get("tos").toString();
            latestPrivacy = metadata.get("privacy").toString();
        } catch (IOException e) {
            LOGGER.error("Failed to fetch latest policies", e);
            context.failure();
            return;
        }
        String currentAcceptedTerms = context.getUser().getFirstAttribute(USER_TERMS_ATTRIBUTE);
        String currentAcceptedPrivacy = context.getUser().getFirstAttribute(USER_PRIVACY_ATTRIBUTE);

        LOGGER.debug("Current accepted terms: " + currentAcceptedTerms);
        LOGGER.debug("Latest terms: " + latestTOS);
        LOGGER.debug("Current accepted privacy: " + currentAcceptedPrivacy);
        LOGGER.debug("Latest privacy: " + latestPrivacy);

        if(Objects.equals(latestTOS, currentAcceptedTerms) && Objects.equals(latestPrivacy, currentAcceptedPrivacy)) {
            LOGGER.debug("User has already accepted the latest terms and conditions");
            return;
        }
        LOGGER.debug("User has not accepted the latest terms and conditions");
        context.getUser().addRequiredAction(PROVIDER_ID);
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        String latestTOSUrl = String.format(policiesBaseUrl, "tos", latestTOS);
        String latestPrivacyUrl = String.format(policiesBaseUrl, "privacy", latestPrivacy);

        Response challenge = context.form()
            .setAttribute("user", context.getAuthenticationSession().getAuthenticatedUser())
            .setAttribute(FORM_TOS_URL_ATTRIBUTE, latestTOSUrl)
            .setAttribute(FORM_PRIVACY_URL_ATTRIBUTE, latestPrivacyUrl)
            .setAttribute(USER_TERMS_ATTRIBUTE, latestTOS)
            .setAttribute(USER_PRIVACY_ATTRIBUTE, latestPrivacy)
            .createForm("terms.ftl");

        context.challenge(challenge);
    }

    @Override
    public void processAction(RequiredActionContext context) {
        context.getUser().removeAttribute(USER_TERMS_ATTRIBUTE.toUpperCase());
        context.getUser().removeAttribute(USER_PRIVACY_ATTRIBUTE.toUpperCase());

        MultivaluedMap<String, String> params = context.getHttpRequest().getDecodedFormParameters();

        if (params.containsKey("cancel")) {
            context.getUser().addRequiredAction(DeleteAccount.PROVIDER_ID);
            context.success();
            return;
        }

        String acceptedTOS = params.getFirst(USER_TERMS_ATTRIBUTE);
        String acceptedPrivacy = params.getFirst(USER_PRIVACY_ATTRIBUTE);

        LOGGER.debug("User accepted terms: " + acceptedTOS);
        LOGGER.debug("User accepted privacy: " + acceptedPrivacy);

        context.getUser().setSingleAttribute(USER_TERMS_ATTRIBUTE, acceptedTOS);
        context.getUser().setSingleAttribute(USER_PRIVACY_ATTRIBUTE, acceptedPrivacy);

        context.success();
    }

    @Override
    public String getDisplayText() {
        return "External Terms and Conditions";
    }

    @Override
    public void close() {

    }
}