/*
 *  Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.conditional.auth.functions.choreo;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.concurrent.FutureCallback;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.identity.application.authentication.framework.AsyncProcess;
import org.wso2.carbon.identity.application.authentication.framework.AsyncReturn;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.JsGraphBuilder;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.conditional.auth.functions.choreo.internal.ChoreoFunctionServiceHolder;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.ConfigProvider;
import org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants;
import org.wso2.carbon.identity.secret.mgt.core.exception.SecretManagementException;
import org.wso2.carbon.identity.secret.mgt.core.model.ResolvedSecret;
import org.wso2.carbon.identity.secret.mgt.core.model.Secret;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.apache.http.HttpHeaders.ACCEPT;
import static org.apache.http.HttpHeaders.CONTENT_TYPE;
import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants.OUTCOME_FAIL;
import static org.wso2.carbon.identity.conditional.auth.functions.common.utils.Constants.OUTCOME_TIMEOUT;

/**
 * Implementation of the {@link CallChoreoFunction}
 */
public class CallChoreoFunctionImpl implements CallChoreoFunction {

    private static final Log LOG = LogFactory.getLog(CallChoreoFunctionImpl.class);
    private static final String TYPE_APPLICATION_JSON = "application/json";
    private static final String AUTHORIZATION = "Authorization";
    private static final String GRANT_TYPE = "grant_type";
    private static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
    private static final String URL_VARIABLE_NAME = "url";
    private static final String CONSUMER_KEY_VARIABLE_NAME = "consumerKey";
    private static final String CONSUMER_KEY_ALIAS_VARIABLE_NAME = "consumerKeyAlias";
    private static final String CONSUMER_SECRET_VARIABLE_NAME = "consumerSecret";
    private static final String CONSUMER_SECRET_ALIAS_VARIABLE_NAME = "consumerSecretAlias";
    private static final String SECRET_TYPE = "ADAPTIVE_AUTH_CALL_CHOREO";
    private static final char DOMAIN_SEPARATOR = '.';
    public static final String ACCESS_TOKEN_KEY = "access_token";
    private final List<String> choreoDomains;
    private static final String BEARER = "Bearer ";
    private static final String BASIC = "Basic ";

    public CallChoreoFunctionImpl() {

        this.choreoDomains = ConfigProvider.getInstance().getChoreoDomains();
    }

    @Override
    public void callChoreo(Map<String, String> connectionMetaData, Map<String, Object> payloadData,
                           Map<String, Object> eventHandlers) {

        AsyncProcess asyncProcess = new AsyncProcess((authenticationContext, asyncReturn) -> {
            String epUrl = connectionMetaData.get(URL_VARIABLE_NAME);
            try {
                if (!isValidChoreoDomain(epUrl)) {
                    LOG.error("Provided Url does not contain a configured choreo domain. Invalid Url: " + epUrl);
                    asyncReturn.accept(authenticationContext, Collections.emptyMap(), Constants.OUTCOME_FAIL);
                    return;
                }
                String accessToken = retrieveAccessToken(authenticationContext);
                if (StringUtils.isEmpty(accessToken)) {
                    LOG.info("Requesting the access token from Choreo");
                    accessToken = requestAccessToken(authenticationContext, authenticationContext.getTenantDomain(), connectionMetaData);
                    storeAccessToken(ACCESS_TOKEN_KEY, accessToken);
                    callChoreoEndpoint(epUrl, asyncReturn, authenticationContext, payloadData, accessToken);
                } else {
                    callChoreoEndpoint(epUrl, asyncReturn, authenticationContext, payloadData, accessToken);
                }
            } catch (IllegalArgumentException e) {
                LOG.error("Invalid endpoint Url: " + epUrl, e);
                asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
            } catch (IOException e) {
                LOG.error("Error while requesting access token from Choreo.", e);
                asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
            } catch (SecretManagementException e) {
                LOG.error("Error while resolving Choreo consumer key or secret.", e);
                asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
            } catch (Exception e) {
                LOG.error("Error while invoking callChoreo.", e);
                asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
            }
        });
        JsGraphBuilder.addLongWaitProcess(asyncProcess, eventHandlers);
    }

    public String getResolvedSecret(String name) throws SecretManagementException {

        ResolvedSecret responseDTO = ChoreoFunctionServiceHolder.getSecretResolveManager()
                .getResolvedSecret(SECRET_TYPE, name);
        return responseDTO.getResolvedSecretValue();
    }

    public void storeAccessToken(String name, String value) throws SecretManagementException {

        Secret secret = new Secret(name);
        secret.setSecretValue(value);
        ChoreoFunctionServiceHolder.getSecretManager().addSecret(SECRET_TYPE, secret);
    }

    private String retrieveAccessToken(AuthenticationContext authContext) throws SecretManagementException {
        String accessToken;
        try {
            accessToken = getResolvedSecret(ACCESS_TOKEN_KEY);
        } catch (SecretManagementException e) {
            accessToken = "";
            LOG.info("Could not retrieve access token for session data key: " + authContext.getContextIdentifier());
        }
        return accessToken;
    }

    private boolean isValidChoreoDomain(String url) {

        if (StringUtils.isBlank(url)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Provided url for domain restriction checking is null or empty.");
            }
            return false;
        }

        if (choreoDomains.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No domains configured for domain restriction. Allowing url by default. Url: " + url);
            }
            return true;
        }

        String domain;
        try {
            domain = getParentDomainFromUrl(url);
        } catch (URISyntaxException e) {
            LOG.error("Error while resolving the domain of the url: " + url, e);
            return false;
        }

        if (StringUtils.isEmpty(domain)) {
            LOG.error("Unable to determine the domain of the url: " + url);
            return false;
        }

        if (choreoDomains.contains(domain)) {
            return true;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Domain: " + domain + " extracted from url: " + url + " is not available in the " +
                    "configured choreo domain list: " + StringUtils.join(choreoDomains, ','));
        }

        return false;
    }

    private String getParentDomainFromUrl(String url) throws URISyntaxException {

        URI uri = new URI(url);
        String parentDomain = null;
        String domain = uri.getHost();
        String[] domainArr;
        if (domain != null) {
            domainArr = StringUtils.split(domain, DOMAIN_SEPARATOR);
            if (domainArr.length != 0) {
                parentDomain = domainArr.length == 1 ? domainArr[0] : domainArr[domainArr.length - 2];
                parentDomain = parentDomain.toLowerCase();
            }
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Parent domain: " + parentDomain + " extracted from url: " + url);
        }
        return parentDomain;
    }

    private String requestAccessToken(AuthenticationContext authenticationContext, String tenantDomain, Map<String, String> connectionMetaData) throws SecretManagementException, IOException, URISyntaxException, InterruptedException {

        String consumerKey;
        if (StringUtils.isNotEmpty(connectionMetaData.get(CONSUMER_KEY_VARIABLE_NAME))) {
            consumerKey = connectionMetaData.get(CONSUMER_KEY_VARIABLE_NAME);
        } else {
            String consumerKeyAlias = connectionMetaData.get(CONSUMER_KEY_ALIAS_VARIABLE_NAME);
            consumerKey = getResolvedSecret(consumerKeyAlias);
        }

        String consumerSecret;
        if (StringUtils.isNotEmpty(connectionMetaData.get(CONSUMER_SECRET_VARIABLE_NAME))) {
            consumerSecret = connectionMetaData.get(CONSUMER_SECRET_VARIABLE_NAME);
        } else {
            String consumerSecretAlias = connectionMetaData.get(CONSUMER_SECRET_ALIAS_VARIABLE_NAME);
            consumerSecret = getResolvedSecret(consumerSecretAlias);
        }

        JSONObject jsonObject = new JSONObject();
        jsonObject.put(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS);
        HttpRequest request = HttpRequest.newBuilder(new URI(ConfigProvider.getInstance().getChoreoTokenEndpoint()))
                .header(ACCEPT, TYPE_APPLICATION_JSON)
                .header(CONTENT_TYPE, TYPE_APPLICATION_JSON)
                .header(AUTHORIZATION, BASIC + Base64.getEncoder().encodeToString((consumerKey + ":" + consumerSecret).getBytes()))
                .POST(HttpRequest.BodyPublishers.ofString(jsonObject.toJSONString()))
                .build();

        HttpClient client = ChoreoFunctionServiceHolder.getInstance().getClientManager().getSynchronousClient(tenantDomain);

        java.net.http.HttpResponse<String> response = client.send(request, java.net.http.HttpResponse.BodyHandlers.ofString());

        int responseCode = response.statusCode();
        if (responseCode == 200) {
            Gson gson = new GsonBuilder().create();
            Map<String, String> responseBody = gson.fromJson(response.body(), HashMap.class);
            String accessToken = responseBody.get(ACCESS_TOKEN_KEY);
            return accessToken;
//            storeAccessToken(ACCESS_TOKEN_KEY, accessToken);
        } else {
            LOG.error("Failed to retrieve access token from Choreo. Response Code: " + responseCode +
                    ". Session data key: " + authenticationContext.getContextIdentifier()
            );
            throw new RuntimeException("Token not found");
        }

    }


    private void callChoreoEndpoint(String endpointUrl, AsyncReturn asyncReturn, AuthenticationContext
            authenticationContext,
                                    Map<String, Object> payloadData, String accessToken) {

        boolean isFailure = false;
        HttpPost request = new HttpPost(endpointUrl);
        request.setHeader(ACCEPT, TYPE_APPLICATION_JSON);
        request.setHeader(CONTENT_TYPE, TYPE_APPLICATION_JSON);
        request.setHeader(AUTHORIZATION, BEARER + accessToken);

        try {
            JSONObject jsonObject = new JSONObject();
            jsonObject.putAll(payloadData);
            request.setEntity(new StringEntity(jsonObject.toJSONString()));
            CloseableHttpAsyncClient client = ChoreoFunctionServiceHolder.getInstance().getClientManager().getClient(
                    authenticationContext.getTenantDomain()
            );
            client.execute(request, new FutureCallback<HttpResponse>() {

                @Override
                public void completed(final HttpResponse response) {

                    try {
                        handleChoreoEndpointResponse(authenticationContext, asyncReturn, response);
                    } catch (Exception e) {
                        LOG.error("Error while proceeding after handling the response from Choreo call for " +
                                "session data key: " + authenticationContext.getContextIdentifier(), e
                        );
                    }
                }

                @Override
                public void failed(final Exception ex) {

                    LOG.error("Failed to invoke Choreo for session data key: " + authenticationContext.getContextIdentifier(), ex);
                    try {
                        String outcome = OUTCOME_FAIL;
                        if ((ex instanceof SocketTimeoutException) || (ex instanceof ConnectTimeoutException)) {
                            outcome = OUTCOME_TIMEOUT;
                        }
                        asyncReturn.accept(authenticationContext, Collections.emptyMap(), outcome);
                    } catch (Exception e) {
                        LOG.error("Error while proceeding after failed response from Choreo " +
                                "call for session data key: " + authenticationContext.getContextIdentifier(), e
                        );
                    }
                }

                @Override
                public void cancelled() {

                    LOG.error("Invocation Choreo for session data key: " + authenticationContext.getContextIdentifier() + " is cancelled.");
                    try {
                        asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
                    } catch (Exception e) {
                        LOG.error("Error while proceeding after cancelled response from Choreo call for session data key: " +
                                authenticationContext.getContextIdentifier(), e
                        );
                    }
                }
            });
        } catch (UnsupportedEncodingException e) {
            LOG.error("Error while constructing request payload for calling choreo endpoint. session data key: " +
                    authenticationContext.getContextIdentifier(), e
            );
            isFailure = true;
        } catch (FrameworkException | IOException e) {
            LOG.error("Error while getting HTTP client for calling the choreo endpoint. session data key: " +
                    authenticationContext.getContextIdentifier(), e
            );
            isFailure = true;
        } catch (Exception e) {
            LOG.error("Error while calling Choreo endpoint. session data key: " + authenticationContext.getContextIdentifier(), e);
            isFailure = true;
        }

        if (isFailure) {
            try {
                asyncReturn.accept(authenticationContext, Collections.emptyMap(), OUTCOME_FAIL);
            } catch (Exception e) {
                LOG.error("Error while trying to return from Choreo call after an exception. session data key: " +
                        authenticationContext.getContextIdentifier(), e
                );
            }
        }
    }

    private void handleChoreoEndpointResponse(AuthenticationContext authenticationContext, AsyncReturn asyncReturn,
                                              final HttpResponse response) throws FrameworkException {

        String outcome;
        JSONObject json = null;
        try {
            int responseCode = response.getStatusLine().getStatusCode();
            if (responseCode == 200) {
                String jsonString = EntityUtils.toString(response.getEntity());
                JSONParser parser = new JSONParser();
                json = (JSONObject) parser.parse(jsonString);
                outcome = Constants.OUTCOME_SUCCESS;
            } else {
                outcome = Constants.OUTCOME_FAIL;
                LOG.info("Received non 200 response code from Choreo: " + responseCode);
            }
        } catch (ParseException e) {
            LOG.error("Error while building response from Choreo call for session data key: " +
                    authenticationContext.getContextIdentifier(), e
            );
            outcome = Constants.OUTCOME_FAIL;
        } catch (IOException e) {
            LOG.error("Error while reading response from Choreo call for session data key: " +
                    authenticationContext.getContextIdentifier(), e
            );
            outcome = Constants.OUTCOME_FAIL;
        } catch (Exception e) {
            LOG.error("Error while processing response from Choreo call for session data key: " +
                    authenticationContext.getContextIdentifier(), e
            );
            outcome = OUTCOME_FAIL;
        }
        asyncReturn.accept(authenticationContext, json != null ? json : Collections.emptyMap(), outcome);
    }

}
