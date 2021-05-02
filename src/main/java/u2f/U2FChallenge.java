package u2f;

import com.google.common.base.Strings;
import lombok.extern.java.Log;

import java.io.Serializable;

@Log
public class U2FChallenge implements Serializable {

    private final String classname = this.getClass().getName();

    /**
     * Supported versions for U2F protocol
     */
    final static String U2F_VERSION_V2 = "U2F_V2";
    final static String FIDO = "FIDO2_0";

    /**
     * Common parameters for a challenge in U2F
     */
    String version;

    /**
     * Constructor that constructs U2F registration challenge parameters for the
     * user specified by username and complying to U2F protocol version specified
     * by u2fversion.
     * @param u2fversion - Version of the U2F protocol being communicated in;
     *                      example : "U2F_V2"
     * @param username   - any non-empty username
     * @throws IllegalArgumentException
     *                   - In case of any error
     */
    public U2FChallenge(String u2fversion, String username) throws IllegalArgumentException {

        if (Strings.isNullOrEmpty(u2fversion) || Strings.isNullOrEmpty(username)) {
            String error = String.format("Incorrect input; username %s , u2fversion %s)", username, u2fversion);
            throw new IllegalArgumentException(error);
        }

        if ( u2fversion.equalsIgnoreCase(U2F_VERSION_V2) || u2fversion.equalsIgnoreCase(FIDO)) {
            version = u2fversion;
        } else {
            log.warning("Protocol passed: " + u2fversion);
            throw new IllegalArgumentException("Protocol passed: " + u2fversion);
        }
    }

    /**
     * Empty constructor since this class implements java.io.Serializable
     */
    protected U2FChallenge() { }
}
