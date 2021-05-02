package transaction.requests;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;


/**
 *
 * @author pleung
 */
public class SVCInfo {

    private int did;
    private String protocol;
    private String authtype;
    private String svcusername;
    private String svcpassword;

    public SVCInfo() { }

    public int getDid() {
        return did;
    }

    public void setDid(int did) {
        this.did = did;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public String getAuthtype() {
        return authtype;
    }

    public void setAuthtype(String authtype) {
        this.authtype = authtype;
    }

    public String getSVCUsername() {
        return svcusername;
    }

    public void setSVCUsername(String svcusername) {
        this.svcusername = svcusername;
    }

    public String getSVCPassword() {
        return svcpassword;
    }

    public void setSVCPassword(String svcpassword) {
        this.svcpassword = svcpassword;
    }

    public JsonObject toJsonObject() {
        JsonObjectBuilder job = Json.createObjectBuilder();
        job.add("did", this.did);
        job.add("protocol", this.protocol);
        job.add("authtype", this.authtype);
        if (this.svcusername != null) {
            job.add("svcusername", this.svcusername);
        }
        if (this.svcpassword != null) {
            job.add("svcpassword", this.svcpassword);
        }
        return job.build();
    }
}
