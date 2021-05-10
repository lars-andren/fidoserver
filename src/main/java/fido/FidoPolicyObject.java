
/**
* Copyright StrongAuth, Inc. All Rights Reserved.
*
* Use of this source code is governed by the GNU Lesser General Public License v2.1
* The license can be found at https://github.com/StrongKey/fido2/blob/master/LICENSE
*/

package fido;

import common.Common;
import common.Constants;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.java.Log;

import javax.json.JsonObject;
import javax.json.JsonString;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.stream.Collectors;

@Builder
@Getter
@Setter
@Log
public class FidoPolicyObject {
    private final String icpId;
    private final Long sid;
    private final Long pid;
    private final String version;
    private final Date startDate;
    private final Date endDate;
    private final AlgorithmsPolicyOptions algorithmsOptions;
    private final String requireCounter;
    private final RpPolicyOptions rpOptions;
    private final Boolean isUserSettingsRequired;
    private final Boolean isStoreSignaturesRequired;
    private final RegistrationPolicyOptions registrationOptions;
    private final AuthenticationPolicyOptions authenticationOptions;
    private final ExtensionsPolicyOptions extensionsOptions;
    private final TrustedAuthenticatorPolicyOptions authenticatorOptions;
    private final ArrayList<String> userVerification;
    private final Integer userPresenceTimeout;
    private final AttestationPolicyOptions attestation;
    private final JWTPolicyOptions jwt;
    private final Integer jwtRenewalWindow;
    private final Integer jwtKeyValidity; 

    private FidoPolicyObject(
            String icpId,
            Long sid,
            Long pid,
            String version,
            Date startDate,
            Date endDate,
            AlgorithmsPolicyOptions algorithmsOptions,
            RpPolicyOptions rpOptions,
            String requireCounter,
            Boolean isUserSettingsRequired,
            Boolean isStoreSignaturesRequired,
            RegistrationPolicyOptions registrationOptions,
            AuthenticationPolicyOptions authenticationOptions,
            ExtensionsPolicyOptions extensionsOptions,
            TrustedAuthenticatorPolicyOptions authenticatorOptions,
            ArrayList<String> userVerification,
            Integer userPresenceTimeout,
            AttestationPolicyOptions attestation,
            JWTPolicyOptions jwt,
            Integer jwtRenewalWindow,
            Integer jwtKeyValidity){
        this.icpId = icpId;
        this.sid = sid;
        this.pid = pid;
        this.version = version;
        this.startDate = startDate;
        this.endDate = endDate;
        this.algorithmsOptions = algorithmsOptions;
        this.rpOptions = rpOptions;
        this.requireCounter = requireCounter;
        this.isUserSettingsRequired = isUserSettingsRequired;
        this.isStoreSignaturesRequired = isStoreSignaturesRequired;
        this.registrationOptions = registrationOptions;
        this.authenticationOptions = authenticationOptions;
        this.extensionsOptions = extensionsOptions;
        this.authenticatorOptions = authenticatorOptions;
        this.userVerification = userVerification;
        this.userPresenceTimeout = userPresenceTimeout;
        this.attestation = attestation;
        this.jwt = jwt;
        this.jwtRenewalWindow = jwtRenewalWindow;
        this.jwtKeyValidity = jwtKeyValidity;
    }

    public static FidoPolicyObject parse(String base64Policy, String icpId, Long sid, Long pid) throws Exception {
        try {
            String policyString = new String(Base64.getUrlDecoder().decode(base64Policy), StandardCharsets.UTF_8);
            JsonObject policyJson = Common.stringToJSON(policyString);

            JsonObject FidoPolicyJson = policyJson.getJsonObject(Constants.POLICY_SYSTEM_FIDO_POLICY);
            JsonObject systemJson = FidoPolicyJson.getJsonObject(Constants.POLICY_SYSTEM);
            
            String startDateString = FidoPolicyJson.getString(Constants.POLICY_SYSTEM_START_DATE);
            Date startDate = new Date(Long.parseLong(startDateString)); 
            

            String endDateString = FidoPolicyJson.getString(Constants.POLICY_SYSTEM_END_DATE);
            Date endDate;
            if(endDateString.equals("")){
                endDate = null;
            } else {
                endDate = new Date(Long.parseLong(endDateString));
            } 
            
            String version = FidoPolicyJson.getString(Constants.POLICY_SYSTEM_VERSION);
            
            AlgorithmsPolicyOptions algorithms = AlgorithmsPolicyOptions.parse(FidoPolicyJson.getJsonObject(Constants.POLICY_ATTR_ALGORITHMS));
           
            RpPolicyOptions rp = RpPolicyOptions.parse(FidoPolicyJson.getJsonObject(Constants.POLICY_ATTR_RP));
         
            String requireCounter = systemJson.getString(Constants.POLICY_ATTR_COUNTER);
            
            ArrayList<String> userVerification = new ArrayList<>(systemJson.getJsonArray(Constants.POLICY_SYSTEM_USER_VERIFICATION).stream()
                    .map(x -> (JsonString) x)
                    .map(x -> x.getString())
                    .collect(Collectors.toList()));
            
            Integer userPresenceTimeout = systemJson.getInt(Constants.POLICY_SYSTEM_USER_PRESENCE_TIMEOUT);
            

            Boolean storeSignatures = Common.handleNonExistantJsonBoolean(systemJson, Constants.POLICY_ATTR_STORESIGNATURES);

            RegistrationPolicyOptions registration = RegistrationPolicyOptions.parse(FidoPolicyJson.getJsonObject(Constants.POLICY_ATTR_REGISTRATION));

            AuthenticationPolicyOptions authentication = AuthenticationPolicyOptions.parse(FidoPolicyJson.getJsonObject(Constants.POLICY_ATTR_AUTHENTICATION));

            ExtensionsPolicyOptions extensions = ExtensionsPolicyOptions.parse(FidoPolicyJson.getJsonObject(Constants.POLICY_ATTR_EXTENSIONS));
            
            TrustedAuthenticatorPolicyOptions aaguids = TrustedAuthenticatorPolicyOptions.parse(systemJson);
            
            AttestationPolicyOptions attestation = AttestationPolicyOptions.parse(FidoPolicyJson.getJsonObject(Constants.POLICY_ATTESTATION));
            
            JWTPolicyOptions jwt = JWTPolicyOptions.parse(FidoPolicyJson.getJsonObject(Constants.POLICY_JWT));
            
            Integer jwtRenewalWindow =  systemJson.getInt(Constants.POLICY_JWT_RENEWAL);
            Integer jwtKeyValidity =  systemJson.getInt(Constants.POLICY_JWT_KEY_VALIDITY);
                            
            return new FidoPolicyObjectBuilder()
                    .icpId(icpId)
                    .sid(sid)
                    .pid(pid)
                    .version(version)
                    .userVerification(userVerification)
                    .userPresenceTimeout(userPresenceTimeout)
                    .startDate(startDate)
                    .endDate(endDate)
                    .algorithmsOptions(algorithms)
                    .rpOptions(rp)
                    .requireCounter(requireCounter)
                    .registrationOptions(registration)
                    .authenticationOptions(authentication)
                    .authenticatorOptions(aaguids)
                    .attestation(attestation)
                    .jwt(jwt)
                    .jwtRenewalWindow(jwtRenewalWindow)
                    .jwtKeyValidity(jwtKeyValidity)
                    .extensionsOptions(extensions)
                    .isStoreSignaturesRequired(storeSignatures)
                    .build();

        } catch (ClassCastException | NullPointerException e) {
            log.severe("Error when parsing FidoPolicyObject: " + e.getMessage());
            throw new Exception(e.getLocalizedMessage());
        } 
    }
}
