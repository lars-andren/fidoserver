package transaction.requests;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;

public class RegistrationRequest {

    private SVCInfo svcinfo;
    private Payload payload;

    public RegistrationRequest() {
        svcinfo = new SVCInfo();
        payload = new Payload();
    }

    public SVCInfo getSVCInfo() {
        return svcinfo;
    }

    public Payload getPayload() {
        return payload;
    }

    public void setMetadata(JsonObject metadata) {
        payload.setMetadata(metadata);
    }

    public void setResponse(JsonObject response) {
        payload.setResponse(response);
    }

    public JsonObject toJsonObject() {
        JsonObjectBuilder job = Json.createObjectBuilder();
        job.add("svcinfo", svcinfo.toJsonObject());
        job.add("payload", payload.toJsonObject());
        return job.build();
    }
}