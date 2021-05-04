package u2f;

import common.Constants;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.java.Log;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import java.io.Serializable;
import java.util.logging.Level;

@Getter
@Setter
@Log
public class U2FAuthenticationChallenge extends U2FChallenge implements Serializable {

    private final String keyhandle;

    private String appid;

    private JsonArray transports;

    public U2FAuthenticationChallenge(String u2fversion, String username, String keyhandlefromDB, String appidfromDB, JsonArray transport_list) throws IllegalArgumentException {
        super(u2fversion, username);

        if (keyhandlefromDB == null || keyhandlefromDB.trim().isEmpty()) {
            throw new IllegalArgumentException("keyhandle cannot be null or empty");
        }

        keyhandle = keyhandlefromDB;
        appid = appidfromDB;
        transports = transport_list;
        log.fine("Created U2FAuthenticationChallenge");
    }

    public final JsonObject toJsonObject(String appidfromfile) {
        JsonObject jsonObj;
        if (appid.equalsIgnoreCase(appidfromfile)) {
            jsonObj = Json.createObjectBuilder()
                    .add(Constants.JSON_USER_KEY_HANDLE_SERVLET, this.keyhandle)
                    .add(Constants.JSON_KEY_TRANSPORT, transports)
                    .add(Constants.JSON_KEY_VERSION, version)
                    .build();
        } else {
            jsonObj = Json.createObjectBuilder()
                    .add(Constants.JSON_USER_KEY_HANDLE_SERVLET, this.keyhandle)
                    .add(Constants.JSON_KEY_TRANSPORT, transports)
                    .add(Constants.JSON_KEY_VERSION, version)
                    .add(Constants.JSON_KEY_APP_ID, appid)
                    .build();
        }

        return jsonObj;
    }

    public final String toJsonString(String appidfromfile) {
        return toJsonObject(appidfromfile).toString();
    }
}

