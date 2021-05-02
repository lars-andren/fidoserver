package u2f;

import common.Constants;
import crypto.CryptoUtil;
import lombok.extern.java.Log;

import javax.json.Json;
import javax.json.JsonObject;
import java.io.Serializable;
import java.util.logging.Level;

@Log
public class U2FRegistrationChallenge extends U2FChallenge implements Serializable {

    /**
     * This class' name - used for logging
     */
    private final String classname = this.getClass().getName();

    private String nonce;

    public U2FRegistrationChallenge(String u2fversion, String username) throws Exception {
        super(u2fversion, username);
        nonce = CryptoUtil.getRandom(Integer.parseInt(SKFSCommon.getConfigurationProperty("skfs.cfg.property.entropylength")));
    }

    /**
     * Get methods to access the challenge parameters
     * @return
     */
    public String getVersion() {
        return version;
    }

    public String getNonce() {
        return nonce;
    }

    /**
     * Converts this POJO into a JsonObject and returns the same.
     * @return JsonObject
     */
    public final JsonObject toJsonObject() {

        JsonObject jsonObj = Json.createObjectBuilder()
                .add(Constants.JSON_KEY_NONCE, this.nonce)
                .add(Constants.JSON_KEY_VERSION, this.version)
                .build();

        return jsonObj;
    }

    /**
     * Converts this POJO into a JsonObject and returns the String form of it.
     * @return String containing the Json representation of this POJO.
     */
    public final String toJsonString() {
        return toJsonObject().toString();
    }
}

