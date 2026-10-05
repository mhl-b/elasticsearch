/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security;

import org.elasticsearch.client.Request;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.SecureString;

import java.io.IOException;
import java.util.Locale;

import static org.hamcrest.Matchers.equalTo;

public class SecondaryAuthIncrementalBulkIT extends SecurityInBasicRestTestCase {

    public void testBulkWithNativeSecondaryAuthUser() throws IOException {
        final String username = "secondary_" + randomAlphaOfLength(8).toLowerCase(Locale.ROOT);
        final String password = "secondary-password";
        final Request putUser = new Request("PUT", "/_security/user/" + username);
        putUser.setJsonEntity(Strings.format("{\"password\":\"%s\",\"roles\":[\"superuser\"]}", password));
        assertOK(adminClient().performRequest(putUser));

        final Request bulk = new Request("POST", "/_bulk");
        bulk.setOptions(
            RequestOptions.DEFAULT.toBuilder()
                .addHeader("es-secondary-authorization", basicAuthHeaderValue(username, new SecureString(password.toCharArray())))
        );
        final StringBuilder body = new StringBuilder();
        for (int i = 0; i < randomIntBetween(1, 50); i++) {
            body.append("{\"index\":{\"_index\":\"secondary_auth_bulk\"}}\n{\"value\":").append(i).append("}\n");
        }
        bulk.setJsonEntity(body.toString());
        final var response = responseAsMap(adminClient().performRequest(bulk));
        assertThat(response.toString(), response.get("errors"), equalTo(false));
    }
}
