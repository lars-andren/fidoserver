package transaction.requests;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;

public class PreregistrationRequest {

    private SVCInfo svcinfo;
    private Payload payload;

    public PreregistrationRequest() {
        svcinfo = new SVCInfo();
        payload = new Payload();
    }

    public SVCInfo getSVCInfo() {
        return svcinfo;
    }

    public Payload getPayload() {
        return payload;
    }

    public void setUsername(String username) {
        payload.setUsername(username);
    }

    public void setDisplayName(String displayName) {
        payload.setDisplayname(displayName);
    }

    public void setOptions(JsonObject options) {
        payload.setOptions(options);
    }

    public void setExtensions(String extensions) {
        payload.setExtensions(extensions);
    }

    public JsonObject toJsonObject(){
        JsonObjectBuilder job = Json.createObjectBuilder();
        job.add("svcinfo", svcinfo.toJsonObject());
        job.add("payload", payload.toJsonObject());
        return job.build();
    }
}
