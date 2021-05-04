package transaction.requests;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;


/**
 *
 * @author pleung
 */
public class SVCInfo {

    private String icpId;
    private String protocol;
    private String authtype;
    private String svcusername;
    private String svcpassword;

    public SVCInfo() { }

    public String getIcpId() {
        return icpId;
    }

    public void setIcpId(String icpId) {
        this.icpId = icpId;
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
        job.add("did", this.icpId);
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
