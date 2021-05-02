package u2f.util;

import common.Common;
import lombok.extern.java.Log;
import transaction.requests.PreregistrationRequest;
import util.ReturnPair;

import javax.ws.rs.core.Response;

@Log
public class U2FVerifier {

    public static ReturnPair<Boolean, Response> checkProtocol(PreregistrationRequest preregistration) {

        ReturnPair<Boolean, Response> returnPair = new ReturnPair(false, null);
        Response response = null;

        if (preregistration.getSVCInfo().getProtocol() == null || preregistration.getSVCInfo().getProtocol().isEmpty()) {
            String error = "Protocol missing or empty";
            log.warning(error);
            response =  Response.status(Response.Status.BAD_REQUEST).entity(error).build();

            returnPair.setReturnSomeValue(true);
        }

        if (!Common.isFIDOProtocolSupported(preregistration.getSVCInfo().getProtocol())) {
            String error = "Protocol " + preregistration.getSVCInfo().getProtocol() + " not supported";
            log.warning(error);
            response = Response.status(Response.Status.BAD_REQUEST).entity(error).build();

            returnPair.setReturnSomeValue(true);
        }

        if (returnPair.returnSomeValue()) {
            returnPair.setValueToReturn(response);
        }

        return returnPair;
    }

    public static ReturnPair<Boolean, Response> checkUsername(PreregistrationRequest preregistration) {

        ReturnPair<Boolean, Response> returnPair = new ReturnPair(false, null);

        if (preregistration.getPayload().getUsername() == null || preregistration.getPayload().getUsername().isEmpty()) {
            String error = "User name missing or empty";
            log.warning(error);

            returnPair.setReturnSomeValue(true);
            returnPair.setValueToReturn(Response.status(Response.Status.BAD_REQUEST).entity(error).build());
        }

        return returnPair;
    }
}
