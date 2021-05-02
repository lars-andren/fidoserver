package transaction.requests;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;

public class PreauthenticationRequest {

    private SVCInfo svcinfo;
    private Payload payload;

    public PreauthenticationRequest() {
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

    public void setOptions(JsonObject options) {
        payload.setOptions(options);
    }

    public JsonObject toJsonObject(){
        JsonObjectBuilder job = Json.createObjectBuilder();
        job.add("svcinfo", svcinfo.toJsonObject());
        job.add("payload", payload.toJsonObject());
        return job.build();
    }
}
