/**
* Copyright StrongAuth, Inc. All Rights Reserved.
*
* Use of this source code is governed by the GNU Lesser General Public License v2.1
* The license can be found at https://github.com/StrongKey/fido2/blob/master/LICENSE
*/
package fido;

import common.Constants;
import lombok.Builder;
import lombok.Getter;

import java.util.ArrayList;
import java.util.stream.Collectors;
import javax.json.JsonObject;
import javax.json.JsonString;

@Getter
@Builder
class TrustedAuthenticatorPolicyOptions {
    private final ArrayList<String> allowedAAGUIDs;

    private TrustedAuthenticatorPolicyOptions(ArrayList<String> allowedAAGUIDs) {
        this.allowedAAGUIDs = allowedAAGUIDs;
    }

    public static TrustedAuthenticatorPolicyOptions parse(JsonObject systemJson) {
        TrustedAuthenticatorPolicyOptionsBuilder trustedAuthenticatorPolicyBuilder = new TrustedAuthenticatorPolicyOptionsBuilder();
        if (systemJson.getJsonArray(Constants.POLICY_AUTHENTICATOR_AAGUIDS) != null) {
            trustedAuthenticatorPolicyBuilder.allowedAAGUIDs(
                    new ArrayList<>(systemJson.getJsonArray(Constants.POLICY_AUTHENTICATOR_AAGUIDS)
                            .stream().map(x -> ((JsonString) x).getString()).collect(Collectors.toList())));
        }
        return trustedAuthenticatorPolicyBuilder.build();


    }
}


