package u2f;

import common.Common;
import common.Constants;
import crypto.CryptoUtil;
import lombok.extern.java.Log;

import javax.json.Json;
import javax.json.JsonObject;
import java.io.Serializable;

@Log
public class U2FRegistrationChallenge extends U2FChallenge implements Serializable {

    private String nonce;

    public U2FRegistrationChallenge(String u2fversion, String username) throws IllegalArgumentException {
        super(u2fversion, username);
        this.nonce = CryptoUtil.getRandom(Integer.parseInt(Common.getProperty("skfs.cfg.property.entropylength")));
    }

    public String getVersion() {
        return version;
    }

    public String getNonce() {
        return this.nonce;
    }

    public final JsonObject toJsonObject() {

        JsonObject jsonObj = Json.createObjectBuilder()
                .add(Constants.JSON_KEY_NONCE, this.nonce)
                .add(Constants.JSON_KEY_VERSION, this.version)
                .build();

        return jsonObj;
    }

    public final String toJsonString() {
        return toJsonObject().toString();
    }
}

