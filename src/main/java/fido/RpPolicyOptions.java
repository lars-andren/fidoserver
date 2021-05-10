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
public class RpPolicyOptions {
    private final String name;
    private final String id;
    private final String icon;

    private RpPolicyOptions(String name, String id, String icon){
        this.name = name;
        this.id = id;
        this.icon = icon;
    }

    public static RpPolicyOptions parse(JsonObject rpJson) {
        return new RpPolicyOptionsBuilder()
                .name(rpJson.getString(Constants.POLICY_RP_NAME, null))
                .id(rpJson.getString(Constants.POLICY_RP_ID, null))
                .icon(rpJson.getString(Constants.POLICY_RP_ICON, null))
                .build();
    }
}
