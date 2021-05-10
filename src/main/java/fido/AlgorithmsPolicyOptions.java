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
import javax.json.JsonString;
import java.util.ArrayList;
import java.util.stream.Collectors;

@Getter
@Builder
public class AlgorithmsPolicyOptions {
    private final ArrayList<String> supportedEllipticCurves;
    private final ArrayList<String> allowedECSignatures;
    private final ArrayList<String> allowedRSASignatures;

    private AlgorithmsPolicyOptions(
            ArrayList<String> supportedEllipticCurves, ArrayList<String> allowedECSignatures,
            ArrayList<String> allowedRSASignatures){
        this.supportedEllipticCurves = supportedEllipticCurves;
        this.allowedECSignatures = allowedECSignatures;
        this.allowedRSASignatures = allowedRSASignatures;
    }

    public static AlgorithmsPolicyOptions parse(JsonObject algoJson) {

        AlgorithmsPolicyOptionsBuilder algoPolicyBuilder = new AlgorithmsPolicyOptionsBuilder();
        if(algoJson.getJsonArray(Constants.POLICY_CRYPTO_ALLOWED_EC_SIGNATURES) != null){
            algoPolicyBuilder.allowedECSignatures(new ArrayList<>(algoJson.getJsonArray(Constants.POLICY_CRYPTO_ALLOWED_EC_SIGNATURES).stream().map(x -> ((JsonString) x).getString()).collect(Collectors.toList())));
        }
        if(algoJson.getJsonArray(Constants.POLICY_CRYPTO_ALLOWED_RSA_SIGNATURES) != null){
            algoPolicyBuilder.allowedRSASignatures(new ArrayList<>(algoJson.getJsonArray(Constants.POLICY_CRYPTO_ALLOWED_RSA_SIGNATURES).stream().map(x -> ((JsonString) x).getString()).collect(Collectors.toList())));
        }
        if(algoJson.getJsonArray(Constants.POLICY_CRYPTO_ELLIPTIC_CURVES) != null){
            algoPolicyBuilder.supportedEllipticCurves(new ArrayList<>(algoJson.getJsonArray(Constants.POLICY_CRYPTO_ELLIPTIC_CURVES).stream().map(x -> ((JsonString) x).getString()).collect(Collectors.toList())));
        }
        return algoPolicyBuilder.build();
    }
}
