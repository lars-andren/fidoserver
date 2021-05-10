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

import javax.json.JsonObject;

@Getter
@Builder
public class AuthenticationPolicyOptions {

    private final String allowCredentials;

    public AuthenticationPolicyOptions(String allowCredentials){
        this.allowCredentials = allowCredentials;
    }

    public static AuthenticationPolicyOptions parse(JsonObject authenticationJson) {
        return new AuthenticationPolicyOptionsBuilder()
                .allowCredentials(authenticationJson.getString(Constants.POLICY_AUTHENTICATION_ALLOWCREDENTIALS, null))
                .build();
    }
}
