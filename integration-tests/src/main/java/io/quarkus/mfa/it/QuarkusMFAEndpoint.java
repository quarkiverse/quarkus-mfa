/*
* Licensed to the Apache Software Foundation (ASF) under one or more
* contributor license agreements.  See the NOTICE file distributed with
* this work for additional information regarding copyright ownership.
* The ASF licenses this file to You under the Apache License, Version 2.0
* (the "License"); you may not use this file except in compliance with
* the License.  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package io.quarkus.mfa.it;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;

import io.quarkus.mfa.runtime.MfaAuthConstants;
import io.quarkus.mfa.runtime.MfaAuthConstants.MfaAuthContext;
import io.quarkus.vertx.http.runtime.CurrentVertxRequest;
import io.vertx.core.json.JsonObject;

@Path("/")
@ApplicationScoped
public class QuarkusMFAEndpoint {

    @Inject
    CurrentVertxRequest reqContext;

    @GET
    @Produces("application/json")
    public String main() {
        JsonObject result = new JsonObject();
        result.put("main", true);
        return result.encodePrettily();
    }

    @GET
    @Path("public")
    @Produces("application/json")
    public String publik() {
        JsonObject result = new JsonObject();
        result.put("public", true);
        return result.encodePrettily();
    }

    @GET
    @Path("mfa_login")
    @Produces("application/json")
    public String login() {
        MfaAuthContext authContext = reqContext.getCurrent().get(MfaAuthConstants.AUTH_CONTEXT_KEY);
        JsonObject result = new JsonObject();
        result.put("action", authContext.getViewAction().toString());
        if (authContext.getViewStatus() != null) {
            result.put("status", authContext.getViewStatus().toString());
        }
        if (authContext.getToptURL() != null) {
            result.put("totpURL", authContext.getToptURL().toString());
        }
        return result.encodePrettily();
    }

    @GET
    @Path("mfa_logout")
    @Produces("application/json")
    public String logout() {
        MfaAuthContext authContext = reqContext.getCurrent().get(MfaAuthConstants.AUTH_CONTEXT_KEY);
        JsonObject result = new JsonObject();
        result.put("action", authContext.getViewAction().toString());
        return result.encodePrettily();
    }
}
