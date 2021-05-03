package api;

import org.springframework.beans.factory.annotation.Autowired;
import transaction.requests.AuthenticationRequest;
import transaction.requests.PreauthenticationRequest;
import transaction.requests.PreregistrationRequest;
import transaction.requests.RegistrationRequest;
import org.springframework.stereotype.Service;
import u2f.U2FServletHelper;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Response;

import static com.sun.xml.internal.ws.api.message.Packet.Status.Response;

/**
 * REST based web services that serve FIDO U2F protocol based functionality.
 *
 */
@Path("/")
@Service
public class Servlet {

    @javax.ws.rs.core.Context
    private HttpServletRequest request;

    @Autowired
    U2FServletHelper u2fHelper;

    authenticateRestRequestBeanLocal authRest;

    public Servlet() { }

    /**
     * Step-1 for fido authenticator registration. This methods generates a
     * challenge and returns the same to the caller.
     */
    @POST
    @Path("/registration/challenge")
    @Consumes({"application/json"})
    @Produces({"application/json"})
    public Response preregister(PreregistrationRequest preregistration) {

        if (!authRest.execute(did, request, preregistration)) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        return u2fHelperBean.preregister(did, preregistration);
    }

    /**
     * Step-2 or last step of fido authenticator registration process. This
     * method receives the u2f registration response parameters which is
     * processed and the registration result is notified back to the caller.
     * <p>
     * Both preregister and register methods are time linked. Meaning, register
     * should happen with in a certain time limit after the preregister is
     * finished; otherwise, the user session would be invalidated.
     */
    @POST
    @Path("/registration")
    @Consumes({"application/json"})
    @Produces({"application/json"})
    public Response register(RegistrationRequest registration) {

        if (!authRest.execute(did, request, registration)) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        return u2fHelperBean.register(did, registration);
    }

    /**
     * Step-1 for fido authenticator authentication. This methods generates a
     * challenge and returns the same to the caller.
     */
    @POST
    @Path("/authentication/challenge")
    @Consumes({"application/json"})
    @Produces({"application/json"})
    public Response preauthenticate(PreauthenticationRequest preauthentication) {

        if (!authRest.execute(did, request, preauthentication)) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        return u2fHelperBean.preauthenticate(did, preauthentication);
    }

    /**
     * Step-2 or last step of fido authenticator authentication process. This
     * method receives the u2f authentication response parameters which is
     * processed and the authentication result is notified back to the caller.
     * <p>
     * Both preauthenticate and authenticate methods are time linked. Meaning,
     * authenticate should happen with in a certain time limit after the
     * preauthenticate is finished; otherwise, the user session would be
     * invalidated.
     */
    @POST
    @Path("/authentication")
    @Consumes({"application/json"})
    @Produces({"application/json"})
    public Response authenticate(AuthenticationRequest authentication) {

        if (!authRest.execute(did, request, authentication)) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        return u2fHelperBean.authenticate(did, authentication);
    }
}