package transaction.requests;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;

public class AuthenticationRequest {

    private SVCInfo svcinfo;
    private Payload payload;

    public AuthenticationRequest() {
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

    public void setTxpayload(String txpayload) {
        payload.setTxpayload(txpayload);
    }

    public void setTxid(String txId) {
        payload.setTxid(txId);
    }

    public JsonObject toJsonObject() {
        JsonObjectBuilder job = Json.createObjectBuilder();
        job.add("svcinfo", svcinfo.toJsonObject());
        job.add("payload", payload.toJsonObject());
        return job.build();
    }
}