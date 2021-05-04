package u2f;

import ch.qos.logback.core.status.Status;
import common.Common;
import common.Constants;
import crypto.CryptoUtil;
import dal.Database;
import lombok.extern.java.Log;
import model.FidoKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import session.SessionType;
import session.UserSessionInfo;
import transaction.requests.PreregistrationRequest;
import u2f.util.U2FVerifier;
import util.Pair;
import util.ReturnPair;

import javax.json.*;
import javax.ws.rs.core.Response;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

@Log
@Service
public class U2FServletHelper {

    @Autowired
    Database database;

    public Response preregister(PreregistrationRequest preregistration) {

        Date in = new Date();
        Date out;
        long thId = Thread.currentThread().getId();
        String ID = thId + "-" + in.getTime();
        String username = preregistration.getPayload().getUsername();
        String protocol = preregistration.getSVCInfo().getProtocol();
        String icpId = preregistration.getSVCInfo().getIcpId();

        //  1. Receive request and print inputs
        log.info("FIDO-MSG-0001 [TXID=" + ID + "]"
                + "\n protocol=" + protocol
                + "\n icpId=" + icpId
                + "\n username=" + username
                + "\n displayname=" + preregistration.getPayload().getDisplayname()
                + "\n options=" + preregistration.getPayload().getOptions()
                + "\n extensions=" + preregistration.getPayload().getExtensions());

        ReturnPair<Boolean, Response> protocolReturn = U2FVerifier.checkProtocol(preregistration);
        if (protocolReturn.returnSomeValue()) {
            return protocolReturn.getValueToReturn();
        }

        ReturnPair<Boolean, Response> usernameReturn = U2FVerifier.checkUsername(preregistration);
        if (usernameReturn.returnSomeValue()) {
            return usernameReturn.getValueToReturn();
        }

        //  3. Do processing - call preauthenticate on every key handle

        U2FRegistrationChallenge regChallenge;
        Pair<U2FRegistrationChallenge, Response> regChallengePair = createU2FRegistrationChallenge(protocol, username);
        if (regChallengePair.getSecond() != null) {
            return regChallengePair.getSecond();
        } else {
            regChallenge = regChallengePair.getFirst();
        }

        String[] authnResponses;
        Pair<String[], Response> authResponsePair = createAuthnChallenges(icpId, protocol, username);
        if (authResponsePair.getSecond() != null) {
            return authResponsePair.getSecond();
        } else {
            authnResponses = authResponsePair.getFirst();
        }

        JsonObject combined_regresponse;
        JsonArray signDataArray = null;
        try {
            if (authnResponses != null) {

                JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
                for (String authresponse : authnResponses) {
                    JsonObject ar;
                    try (JsonReader jsonReader = Json.createReader(new StringReader(authresponse))) {
                        ar = jsonReader.readObject();
                    }
                    arrayBuilder.add(ar);
                }

                signDataArray = arrayBuilder.build();

                log.fine("Signdata array length = " + authnResponses.length);
            }

            //building regreq array
            JsonArrayBuilder regarrayBuilder = Json.createArrayBuilder();
            JsonObject regObj;
            try (JsonReader jsonReader = Json.createReader(new StringReader(regChallenge.toJsonString()))) {
                regObj = jsonReader.readObject();
            }
            regarrayBuilder.add(regObj);

            if (signDataArray == null) {
                combined_regresponse = Json.createObjectBuilder()
                        .add(Constants.JSON_KEY_REGISTERREQUEST, regarrayBuilder.build())
                        .build();
            } else {
                combined_regresponse = Json.createObjectBuilder()
                        .add(Constants.JSON_KEY_REGISTERREQUEST, regarrayBuilder.build())
                        .add(Constants.JSON_KEY_REGISTEREDKEY, signDataArray)
                        .build();
            }
        } catch (Exception e) {
            String error = "Exception during challenge generation: " + e.getMessage();
            log.severe(error);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(error).build();
        }

        // Build the output json object
        String response = Json.createObjectBuilder()
                .add(Constants.JSON_KEY_SERVLET_RETURN_RESPONSE, combined_regresponse)
                .build().toString();

        out = new Date();
        long rt = out.getTime() - in.getTime();

        log.info("FIDO-MSG-0002" + "[TXID=" + ID + ", START=" + in.getTime() + ", FINISH=" + out.getTime()
                + ", TTC=" + rt + "]" + "\nU2FRegistration Challenge parameters = " + response);
        return Response.ok().entity(response).build();
    }

    private Pair<U2FRegistrationChallenge, Response> createU2FRegistrationChallenge(String protocol, String username) {

        Pair<U2FRegistrationChallenge, Response> pair = new Pair<>();
        U2FRegistrationChallenge regChallenge = null;
        try {
            regChallenge = new U2FRegistrationChallenge(protocol, username);

            log.fine("Username got challenge " + regChallenge.toJsonString());

            if (regChallenge.getNonce() == null) {

                log.severe("Could not generate nonce for challenge.");
                pair.setSecond(Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Could not generate nonce for challenge.").build());
            } else {
                String nonce = regChallenge.getNonce();
                String nonceHash = Common.getDigest(nonce, "SHA-256");

                UserSessionInfo session = new UserSessionInfo(username, nonce, SessionType.REGISTER, "", "");
                session.setMapkey(nonceHash);

                log.fine("Session created for username=" + username);
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | UnsupportedEncodingException e) {
            String error = "Exception during challenge generation: " + e.getMessage();
            log.severe(error);
            pair.setSecond(Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(error).build());
        }

        pair.setFirst(regChallenge);
        return pair;
    }

    private Pair<String[], Response> createAuthnChallenges(String icpId, String protocol, String username) {

        Pair<String[], Response> pair = new Pair<>();
        String[] authresponses = null;
        try {
            log.fine("Making a silent preauthenticate call to fetch all the key handles.");

            Collection<FidoKey> kh_coll = database.getByUsername(icpId, username);
            if (kh_coll != null) {
                authresponses = new String[kh_coll.size()];
                Iterator<FidoKey> it = kh_coll.iterator();
                int i = 0;

                while (it.hasNext()) {
                    FidoKey key = (FidoKey) it.next();
                    if (key != null) {
                        String keyhandle = decryptKH(key.getKeyhandle());

                        // Do a silent preauthenticate call to get auth wsresponse for this key handle.
                        // Fetch transports and create a jsonarray and pass it on to the auth challenge object
                        U2FAuthenticationChallenge authChallenge = new U2FAuthenticationChallenge(
                                protocol,
                                username,
                                keyhandle,
                                key.getAppid(),
                                Common.getTransportJson(key.getTransports().intValue()));

                        authresponses[i] = authChallenge.toJsonString(key.getAppid());
                        i++;
                    }
                }
            }
        } catch (Exception e) {
            log.severe("Exception when creating preauth: " + e.getMessage());
            pair.setSecond(Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build());
        }

        pair.setFirst(authresponses);
        return pair;
    }

    /**
     * Method that performs registration process in FIDO U2F protocol. This
     * method receives the request, performs basic input checks, parses the
     * sessionid from the U2F registration response parameters passed. Based on
     * the sessionid, the user session is validated. If found valid, the
     * registration process is handed over to an EJB. Upon getting response from
     * the EJB, this method persists the registration information to the
     * database. The user session at this point is removed or invalidated even
     * if the registration fails.
     *
     * NOTE : The U2F protocol version that is being used is decided based on
     * the structure of the regresponseJson; mostly relying on json keys.
     *
     * @param did - FIDO domain id
     * @param registration String request body for registration
     *
     * @return - A Json in String format. The Json will have 3 key-value pairs;
     * 1. 'Response' : String, with a simple message telling if the process was
     * successful or not. 2. 'Message' : String, with a list of messages that
     * explain the process. 3. 'Error' : String, with error message incase
     * something went wrong. Will be empty if successful.
     */
    @Override
    public Response register(Long did, RegistrationRequest registration) {

        Date in = new Date();
        Date out;
        long thId = Thread.currentThread().getId();
        String ID = thId + "-" + in.getTime();
        //  1. Receive request and print inputs
        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.INFO, "FIDO-MSG-0003", "[TXID=" + ID + "]"
                + "\n did=" + did
                + "\n protocol=" + registration.getSVCInfo().getProtocol()
                + "\n response=" + registration.getPayload().getResponse()
                + "\n metadata=" + registration.getPayload().getMetadata());

        //  2. Input checks
        if (registration.getPayload().getResponse() == null || registration.getPayload().getResponse().isEmpty()) {
            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0004", "");
            return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.getMessageProperty("FIDO-ERR-0004")).build();
        }

        if (registration.getPayload().getMetadata() == null || registration.getPayload().getMetadata().isEmpty()) {
            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0016", "");
            return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.getMessageProperty("FIDO-ERR-0016")).build();
        }

        if (registration.getSVCInfo().getProtocol() == null || registration.getSVCInfo().getProtocol().isEmpty()) {
            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0002", " protocol");
            return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.getMessageProperty("FIDO-ERR-0002") + " protocol").build();
        }
        if (!SKFSCommon.isFIDOProtocolSupported(registration.getSVCInfo().getProtocol())) {
            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, SKFSCommon.getMessageProperty("FIDO-ERR-5002"), registration.getSVCInfo().getProtocol());
            return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.getMessageProperty("FIDO-ERR-5002") + registration.getSVCInfo().getProtocol()).build();
        }

        String responseJSON;

        try {
            if (registration.getSVCInfo().getProtocol().equalsIgnoreCase(SKFSConstants.FIDO_PROTOCOL_VERSION_U2F_V2)) {
                responseJSON = U2FRegejb.execute(did, registration.getPayload().getResponse().toString(), registration.getPayload().getMetadata().toString(), registration.getSVCInfo().getProtocol());
            } else {
                responseJSON = FIDO2Regejb.execute(did, registration.getPayload().getResponse().toString(), registration.getPayload().getMetadata().toString());
            }
        } catch (IllegalArgumentException | SKIllegalArgumentException ex) {
            return Response.status(Response.Status.BAD_REQUEST).entity(ex.getMessage()).build();
        } catch (Exception ex) {
            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0001", ex.getMessage());
            return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.getMessageProperty("FIDO-ERR-0001") + ex.getMessage()).build();
        }
        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.FINE, "FIDO-MSG-0037", "");

        out = new Date();
        long rt = out.getTime() - in.getTime();
        //  1. Print output and Return
        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.INFO, "FIDO-MSG-0004", "[TXID=" + ID + ", START=" + in.getTime() + ", FINISH=" + out.getTime() + ", TTC=" + rt + "]" + "\nResponse = " + responseJSON);
        return Response.ok().entity(responseJSON).build();
    }

    /*
     *************************************************************************
     *                                                888    888
     *                                                888    888
     *                                                888    888
     *    88888b.  888d888  .d88b.   8888b.  888  888 888888 88888b.
     *    888 "88b 888P"   d8P  Y8b     "88b 888  888 888    888 "88b
     *    888  888 888     88888888 .d888888 888  888 888    888  888
     *    888 d88P 888     Y8b.     888  888 Y88b 888 Y88b.  888  888
     *    88888P"  888      "Y8888  "Y888888  "Y88888  "Y888 888  888
     *    888
     *    888
     *    888
     ************************************************************************
     */
    /**
     * Method that performs pre-auth process in FIDO U2F protocol. This method
     * receives the request, performs basic input checks and then looks into the
     * database for the number of FIDO authenticators the user has already
     * successfully registered. For each registered key, this method hands over
     * the pre-authenticate process to an EJB and waits for the response. For
     * each key, up on receiving U2F Authentication nonce parameters from the
     * EJB, there is a user session entry added to the session map maintained in
     * memory.
     *
     * @param did - FIDO domain id
     * @param preauthentication - U2F protocol version to comply with.
     *
     * @return - A Json in String format. The Json will have 3 key-value pairs;
     * 1. 'Challenge' : 'U2F Auth Challenge parameters; a json again' 2.
     * 'Message' : String, with a list of messages that explain the process. 3.
     * 'Error' : String, with error message incase something went wrong. Will be
     * empty if successful.
     */
    @Override
    public Response preauthenticate(Long did, PreauthenticationRequest preauthentication) {

        Date in = new Date();
        Date out;
        long thId = Thread.currentThread().getId();
        String ID = thId + "-" + in.getTime();
        //  1. Receive request and print inputs
        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.INFO, "FIDO-MSG-0005", "[TXID=" + ID + "]"
                + "\n did=" + did
                + "\n protocol=" + preauthentication.getSVCInfo().getProtocol()
                + "\n username=" + preauthentication.getPayload().getUsername()
                + "\n options=" + preauthentication.getPayload().getOptions()
                + "\n extensions" + preauthentication.getPayload().getExtensions());

        //  2. Input checks
        if (preauthentication.getSVCInfo().getProtocol() == null || preauthentication.getSVCInfo().getProtocol().isEmpty()) {
            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0002", " protocol");
            return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0002")
                    + " protocol")).build();
        }
        if (!SKFSCommon.isFIDOProtocolSupported(preauthentication.getSVCInfo().getProtocol())) {
            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-5002", preauthentication.getSVCInfo().getProtocol());
            return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-5002")
                    + preauthentication.getSVCInfo().getProtocol())).build();
        }

        //  3. Retrieve data from payload
        //  fetch the username
        //  fetch extensions (if they exist)
        JsonObject jsonOptions = null;
        if (preauthentication.getPayload().getOptions() != null ) { //&& !preauthentication.getPayload().getOptions().isEmpty()) {
//            StringReader stringreader = new StringReader(preauthentication.getPayload().getOptions().toString());
//            JsonReader jsonreader = Json.createReader(stringreader);
            jsonOptions = preauthentication.getPayload().getOptions();
        }

        JsonObject jsonExtensions = null;
        if (preauthentication.getPayload().getExtensions() != null && !preauthentication.getPayload().getExtensions().isEmpty()) {
            StringReader stringreader = new StringReader(preauthentication.getPayload().getExtensions());
            JsonReader jsonreader = Json.createReader(stringreader);
            jsonExtensions = jsonreader.readObject();
        }

        if (preauthentication.getPayload().getUsername() == null || preauthentication.getPayload().getUsername().isEmpty()) {
            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0002", " username");
            return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0002")
                    + " username")).build();
        }

        if (preauthentication.getPayload().getUsername().trim().length() > applianceCommon.getMaxLenProperty("appliance.cfg.maxlen.256charstring")) {
            return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.getMessageProperty("FIDOJPA-ERR-1002") + " username").build();
        }

        String appid = applianceMaps.getDomain(did).getSkfeAppid();

        //  3. Do processing
        //  Look into the database to check for key handles
        String[] keyhandles;
        String[] upkeys;
        String[] appids;
        JsonArray[] transports;
        Long[] regkeyids;
        Short[] serverids;
        String responseJSON;
        if (preauthentication.getSVCInfo().getProtocol().equalsIgnoreCase(SKFSConstants.FIDO_PROTOCOL_VERSION_U2F_V2)) {
            try {
                SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.FINE, "FIDO-MSG-0031", "");
                Collection<FidoKeys> kh_coll
                        = getkeybean.getByUsernameStatus(did, preauthentication.getPayload().getUsername(), applianceConstants.ACTIVE_STATUS);
                if (kh_coll == null || kh_coll.size() <= 0) {
                    SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0007", "");
                    return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0007"))).build();
                }

                keyhandles = new String[kh_coll.size()];
                upkeys = new String[kh_coll.size()];
                appids = new String[kh_coll.size()];
                regkeyids = new Long[kh_coll.size()];
                serverids = new Short[kh_coll.size()];
                transports = new JsonArray[kh_coll.size()];

                Iterator it = kh_coll.iterator();
                int i = 0;

                //  Populate all key handles and their respective origins.
                SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.FINE, "FIDO-MSG-0032", "");
                while (it.hasNext()) {
                    FidoKeys key = (FidoKeys) it.next();
                    if (key != null) {
                        String mapkey = key.getFidoKeysPK().getSid() + "-" + key.getFidoKeysPK().getDid() + "-" + key.getFidoKeysPK().getUsername() + "-" + key.getFidoKeysPK().getFkid();
                        FidoKeysInfo fkinfoObj = new FidoKeysInfo(key);
                        skceMaps.getMapObj().put(SKFSConstants.MAP_FIDO_KEYS, mapkey, fkinfoObj);
                        keyhandles[i] = decryptKH(key.getKeyhandle());
                        upkeys[i] = key.getPublickey();
                        regkeyids[i] = key.getFidoKeysPK().getFkid();
                        serverids[i] = key.getFidoKeysPK().getSid();
                        appids[i] = key.getAppid();
                        transports[i] = SKFSCommon.getTransportJson(key.getTransports().intValue());
                        i++;
                    }
                }

            } catch (Exception ex) {
                ex.printStackTrace();
                SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0008", ex.getMessage());
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0008")
                        + ex.getMessage())).build();
            }

            JsonObject jsonObject = null;
            U2FAuthenticationChallenge[] authresponses
                    = new U2FAuthenticationChallenge[keyhandles.length];
            JsonArray signDataArray;
            try {
                //  For every keyhandle found, make a preauthenticate call and get authresponse
                //  also add a user session for every preauthenticate call.
                for (int j = 0; j < keyhandles.length; j++) {
                    FEreturn fer = u2fpreauthbean.execute(did, preauthentication.getSVCInfo().getProtocol(), preauthentication.getPayload().getUsername(), keyhandles[j], appids[j], transports[j]);
                    if (fer != null) {
                        authresponses[j] = (U2FAuthenticationChallenge) fer.getResponse();
                    }
                }
                SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.FINE, "FIDO-MSG-0026",
                        " key handles count = " + keyhandles.length);

                if (authresponses != null) {
                    String nonce = U2FUtility.getRandom(Integer.parseInt(SKFSCommon.getConfigurationProperty("skfs.cfg.property.entropylength")));

                    JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
                    JsonArrayBuilder allowedCredBuilder = Json.createArrayBuilder();
                    for (int k = 0; k < authresponses.length; k++) {
                        U2FAuthenticationChallenge authChallenge = authresponses[k];

                        //  fetch the details of auth nonce
                        String keyhandle = authChallenge.getKeyhandle();
                        JsonArray trasnportArrsy = authChallenge.getTransports();
                        String KHHash = SKFSCommon.getDigest(keyhandle, "SHA-256");

                        //  add a user session of type preauthenticate.
                        UserSessionInfo session = new UserSessionInfo(preauthentication.getPayload().getUsername(),
                                nonce, appid, SKFSConstants.FIDO_USERSESSION_AUTH, upkeys[k], "");
                        session.setFkid(regkeyids[k]);
                        session.setSkid(serverids[k]);
                        session.setSid(applianceCommon.getServerId().shortValue());
                        skceMaps.getMapObj().put(SKFSConstants.MAP_USER_SESSION_INFO, KHHash, session);

                        //replicate map to other server
                        session.setMapkey(KHHash);
                        try {
                            if (applianceCommon.replicate()) {
                                replObj.execute(applianceConstants.ENTITY_TYPE_MAP_USER_SESSION_INFO, applianceConstants.REPLICATION_OPERATION_HASHMAP_ADD, applianceCommon.getServerId().toString(), session);
                            }
                        } catch (Exception e) {
                            throw new RuntimeException(e.getLocalizedMessage());
                        }
                        //end publish
                        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.FINE, "FIDO-MSG-0021", " username=" + preauthentication.getPayload().getUsername());

                        arrayBuilder.add(authChallenge.toJsonObject(appid));
                        //                    allowedCredBuilder.add(Json.createObjectBuilder().add("type", "public-key").add("id", keyhandle).add("transports", trasnportArrsy));
                        allowedCredBuilder.add(Json.createObjectBuilder().add("type", "public-key").add("id", keyhandle)); // TODO: fix transport array (removed it)
                    }
                    signDataArray = arrayBuilder.build();
                    if (signDataArray == null) {
                        jsonObject = Json.createObjectBuilder()
                                .add(SKFSConstants.JSON_KEY_NONCE, nonce)
                                .add(SKFSConstants.JSON_KEY_APP_ID, appid)
                                .add(SKFSConstants.JSON_KEY_REGISTEREDKEY, "").
                                        build();
                    } else {
                        jsonObject = Json.createObjectBuilder()
                                .add(SKFSConstants.JSON_KEY_NONCE, nonce)
                                .add(SKFSConstants.JSON_KEY_APP_ID, appid)
                                .add(SKFSConstants.JSON_KEY_REGISTEREDKEY, signDataArray).
                                        build();
                    }
                }
            } catch (NoSuchAlgorithmException | NoSuchProviderException | UnsupportedEncodingException ex) {
                SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0001", ex.getMessage());
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0001")
                        + ex.getMessage())).build();
            }
            responseJSON = Json.createObjectBuilder()
                    .add(SKFSConstants.JSON_KEY_SERVLET_RETURN_RESPONSE, jsonObject)
                    .build().toString();
        } else {
            try {
                responseJSON = fido2preauthbean.execute(did, preauthentication.getPayload().getUsername(), jsonOptions, jsonExtensions);
            } catch (IllegalArgumentException | SKIllegalArgumentException ex) {
                return Response.status(Response.Status.BAD_REQUEST).entity(ex.getMessage()).build();
            }
        }

        // Build the output json object
        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.FINE, "FIDO-MSG-0036", "");

        out = new Date();
        long rt = out.getTime() - in.getTime();
        //  5. Print output and Return
        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.INFO, "FIDO-MSG-0006", "[TXID=" + ID + ", START=" + in.getTime() + ", FINISH=" + out.getTime() + ", TTC=" + rt + "]"
                + "\nU2FAuthentication Challenge parameters = " + responseJSON);
        return Response.ok().entity(responseJSON).build();
    }

    @Override
    public Response preauthorize(Long did, PreauthorizeRequest preauthorize) {

        Date in = new Date();
        Date out;
        long thId = Thread.currentThread().getId();
        String ID = thId + "-" + in.getTime();
        //  1. Receive request and print inputs
        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.INFO, "FIDO-MSG-0013", "[TXID=" + ID + "]"
                + "\n did=" + did
                + "\n protocol=" + preauthorize.getSVCInfo().getProtocol()
                + "\n username=" + preauthorize.getPayload().getUsername()
                + "\n txid=" + preauthorize.getPayload().getTxid()
                + "\n txpayload=" + preauthorize.getPayload().getTxpayload()
                + "\n options=" + preauthorize.getPayload().getOptions()
                + "\n extensions" + preauthorize.getPayload().getExtensions());

        //  2. Input checks
        if (preauthorize.getSVCInfo().getProtocol() == null || preauthorize.getSVCInfo().getProtocol().isEmpty()) {
            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0002", " protocol");
            return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0002")
                    + " protocol")).build();
        }
        if (!SKFSCommon.isFIDOProtocolSupported(preauthorize.getSVCInfo().getProtocol())) {
            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-5002", preauthorize.getSVCInfo().getProtocol());
            return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-5002")
                    + preauthorize.getSVCInfo().getProtocol())).build();
        }

        //  3. Retrieve data from payload
        //  fetch the username
        //  fetch extensions (if they exist)
        JsonObject jsonOptions = null;
        if (preauthorize.getPayload().getOptions() != null ) { //&& !preauthentication.getPayload().getOptions().isEmpty()) {
//            StringReader stringreader = new StringReader(preauthentication.getPayload().getOptions().toString());
//            JsonReader jsonreader = Json.createReader(stringreader);
            jsonOptions = preauthorize.getPayload().getOptions();
        }

        JsonObject jsonExtensions = null;
        if (preauthorize.getPayload().getExtensions() != null && !preauthorize.getPayload().getExtensions().isEmpty()) {
            StringReader stringreader = new StringReader(preauthorize.getPayload().getExtensions());
            JsonReader jsonreader = Json.createReader(stringreader);
            jsonExtensions = jsonreader.readObject();
        }

        if (preauthorize.getPayload().getUsername() == null || preauthorize.getPayload().getUsername().isEmpty()) {
            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0002", " username");
            return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0002")
                    + " username")).build();
        }

        if (preauthorize.getPayload().getUsername().trim().length() > applianceCommon.getMaxLenProperty("appliance.cfg.maxlen.256charstring")) {
            return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.getMessageProperty("FIDOJPA-ERR-1002") + " username").build();
        }

        String responseJSON;
        if (preauthorize.getSVCInfo().getProtocol().equalsIgnoreCase(SKFSConstants.FIDO_PROTOCOL_VERSION_U2F_V2)) {
            // not implemented
            return Response.status(Response.Status.NOT_IMPLEMENTED).entity("U2F not being implemeted").build();
        } else {
            try {
                responseJSON = fido2preauthbean.executePreAuthorize(did, preauthorize.getPayload().getUsername(), preauthorize.getPayload().getTxid(), preauthorize.getPayload().getTxpayload(), jsonOptions, jsonExtensions);
            } catch (IllegalArgumentException | SKIllegalArgumentException ex) {
                return Response.status(Response.Status.BAD_REQUEST).entity(ex.getMessage()).build();
            }
        }

        // Build the output json object
        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.FINE, "FIDO-MSG-0036", "");

        out = new Date();
        long rt = out.getTime() - in.getTime();
        //  5. Print output and Return
        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.INFO, "FIDO-MSG-0014", "[TXID=" + ID + ", START=" + in.getTime() + ", FINISH=" + out.getTime() + ", TTC=" + rt + "]"
                + "\nU2FAuthentication Challenge parameters = " + responseJSON);
        return Response.ok().entity(responseJSON).build();
    }

    /*
     ************************************************************************
     *                        888    888                        888    d8b                   888
     *                        888    888                        888    Y8P                   888
     *                        888    888                        888                          888
     *       8888b.  888  888 888888 88888b.   .d88b.  88888b.  888888 888  .d8888b  8888b.  888888  .d88b.
     *          "88b 888  888 888    888 "88b d8P  Y8b 888 "88b 888    888 d88P"        "88b 888    d8P  Y8b
     *      .d888888 888  888 888    888  888 88888888 888  888 888    888 888      .d888888 888    88888888
     *      888  888 Y88b 888 Y88b.  888  888 Y8b.     888  888 Y88b.  888 Y88b.    888  888 Y88b.  Y8b.
     *      "Y888888  "Y88888  "Y888 888  888  "Y8888  888  888  "Y888 888  "Y8888P "Y888888  "Y888  "Y8888
     *
     ************************************************************************
     */
    /**
     * Method that performs authentication process in FIDO U2F protocol. This
     * method receives the request, performs basic input checks, parses the
     * sessionid from the U2F registration response parameters passed. Based on
     * the sessionid, the user session is validated. If found valid, the
     * authentication process is handed over to an EJB. Upon getting response
     * from the EJB, this method persists the Authentication information to the
     * database. This would contain user key modified location, modification
     * time and the counter. The user session at this point is removed or
     * invalidated even if the registration fails.
     *
     * @param did - FIDO domain id
     * @param authentication - A stringified json with signresponse and sign
     * metadata embedded into it.
     *
     * Example: { "response": { "clientData": "...", "keyHandle": "...",
     * "signatureData": "..." }, "metadata": { "version": "1.0",
     * "modify_location": "Sunnyvale, CA" } }
     *
     * @return - A Json in String format. The Json will have 3 key-value pairs;
     * 1. 'Response' : String, with a simple message telling if the process was
     * successful or not. 2. 'Message' : String, with a list of messages that
     * explain the process. 3. 'Error' : String, with error message incase
     * something went wrong. Will be empty if successful.
     */
    @Override
    public Response authenticate(Long did, AuthenticationRequest authentication, String agent, String cip) {

        Date in = new Date();
        Date out;
        long thId = Thread.currentThread().getId();
        String ID = thId + "-" + in.getTime();
        //  1. Receive request and print inputs
        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.INFO, "FIDO-MSG-0007", "[TXID=" + ID + "]"
                + "\n did=" + did
                + "\n protocol=" + authentication.getSVCInfo().getProtocol()
                + "\n response=" + authentication.getPayload().getResponse()
                + "\n metadata=" + authentication.getPayload().getMetadata());

        //  2. Input checks
        if (authentication.getPayload().getResponse() == null || authentication.getPayload().getResponse().isEmpty()) {
            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0010", "");
            return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0010"))).build();
        }

        if (authentication.getPayload().getMetadata() == null || authentication.getPayload().getMetadata().isEmpty()) {
            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0017", "");
            return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0017"))).build();
        }

        //  4. Finish authentication
        String responseJSON;
        try {

            if (authentication.getSVCInfo().getProtocol().equalsIgnoreCase(SKFSConstants.FIDO_PROTOCOL_VERSION_U2F_V2)) {
                //  fetch needed fields from authresponse
                String browserdata = (String) applianceCommon.getJsonValue(authentication.getPayload().getResponse().toString(),
                        SKFSConstants.JSON_KEY_CLIENTDATA, "String");
                if (browserdata == null || browserdata.isEmpty()) {
                    SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0011", " Missing 'clientData'");
                    return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0011")
                            + " Missing 'clientData'")).build();
                }

                //parse browserdata
                try {
                    String browserdataJson = new String(Base64.getUrlDecoder().decode(browserdata), "UTF-8");
                    JsonReader jsonReader = Json.createReader(new StringReader(browserdataJson));
                    JsonObject jsonObject = jsonReader.readObject();
                    jsonReader.close();

                    String bdreqtype = jsonObject.getString(SKFSConstants.JSON_KEY_REQUESTTYPE);
                    String bdnonce = jsonObject.getString(SKFSConstants.JSON_KEY_NONCE);
                    String bdorigin = jsonObject.getString(SKFSConstants.JSON_KEY_SERVERORIGIN);
                    if (bdreqtype == null || bdnonce == null || bdorigin == null) {
                        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE,
                                SKFSCommon.getMessageProperty("FIDO-ERR-5011"), " Missing 'registrationData'");
                        return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-5011")
                                + " Missing 'registrationData'")).build();
                    }
                } catch (Exception ex) {
                    SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE,
                            SKFSCommon.getMessageProperty("FIDO-ERR-5011"), " Invalid 'clientDATA'");
                    return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-5011")
                            + " Invalid 'clientDATA'")).build();
                }

                String signdata = (String) applianceCommon.getJsonValue(authentication.getPayload().getResponse().toString(),
                        SKFSConstants.JSON_KEY_SIGNATUREDATA, "String");
                if (signdata == null || signdata.isEmpty()) {
                    SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0011", " Missing 'signatureData'");
                    return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0011")
                            + " Missing 'signatureData'")).build();
                }

                String keyhandle = (String) applianceCommon.getJsonValue(authentication.getPayload().getResponse().toString(),
                        SKFSConstants.JSON_USER_KEY_HANDLE_SERVLET, "String");
                if (keyhandle == null || keyhandle.isEmpty()) {
                    SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0011", " Missing 'keyHandle'");
                    return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0011")
                            + " Missing 'keyHandle'")).build();
                }

                //  fetch version and modifylocation from metadata
                String version = (String) applianceCommon.getJsonValue(authentication.getPayload().getMetadata().toString(),
                        SKFSConstants.FIDO_METADATA_KEY_VERSION, "String");
                if (version == null || version.isEmpty()) {
                    SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0019", " Missing metadata - version");
                    return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0019") + " Missing metadata - version")).build();
                }

                String modifyloc = (String) applianceCommon.getJsonValue(authentication.getPayload().getMetadata().toString(),
                        SKFSConstants.FIDO_METADATA_KEY_MODIFY_LOC, "String");
                if (modifyloc == null || modifyloc.isEmpty()) {
                    SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0019", " Missing metadata - modifylocation");
                    return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0019") + " Missing metadata - modifylocation")).build();
                }

                String username_received = (String) applianceCommon.getJsonValue(authentication.getPayload().getMetadata().toString(),
                        SKFSConstants.FIDO_METADATA_KEY_USERNAME, "String");
                if (username_received == null || username_received.isEmpty()) {
                    SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0019", " Missing metadata - username");
                    return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0019")
                            + " Missing metadata - username")).build();
                }

                long regkeyid;
                short serverid;
                String username = "";
                String KHhash;
                String challenge = null;
                String appid_Received = "";

                try {
                    //  calculate the hash of keyhandle received
                    KHhash = SKFSCommon.getDigest(keyhandle, "SHA-256");
                } catch (NoSuchAlgorithmException | NoSuchProviderException | UnsupportedEncodingException ex) {
                    SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0001", " Error generating hash");
                    return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0001") + " Error generating hash")).build();
                }

                //  Look for the sessionid in the sessionmap and retrieve the username
                UserSessionInfo user = (UserSessionInfo) skceMaps.getMapObj().get(SKFSConstants.MAP_USER_SESSION_INFO, KHhash);
                if (user == null) {
                    SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0006", "");
                    return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0006"))).build();
                } else if (user.getSessiontype().equalsIgnoreCase(SKFSConstants.FIDO_USERSESSION_AUTH)) {
                    username = user.getUsername();
                    SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.FINE, "FIDO-MSG-0022", " username=" + username);

                    appid_Received = user.getAppid();
                    challenge = user.getNonce();
                    SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.FINE, "FIDO-MSG-0042", " appid=" + appid_Received);
                }

                //verify that the call is for the right user
                if (!username.equalsIgnoreCase(username_received)) {
                    //throw erro saying wrong username sent
                    return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0037"))).build();
                }

                //appid verifier
                String origin = SKFSCommon.getOriginfromBrowserdata(browserdata);
                if (!originverifierbean.execute(appid_Received, origin)) {
                    SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0032", "");
                    return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0032")
                            + " : " + appid_Received + "-" + origin)).build();
                }

                //  3. Do processing
                //  fetch the user public key from the session map.
                String userpublickey = user.getUserPublicKey();
                regkeyid = user.getFkid();
                serverid = user.getSkid();

                //  instantiate the fido interface and send the information for processing
                FEreturn fer;

                try {
                    fer = u2fauthbean.execute(did, authentication.getSVCInfo().getProtocol(), authentication.getPayload().getResponse().toString(), userpublickey, challenge, appid_Received);
                } catch (SKFEException ex) {
                    SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0001", ex.getLocalizedMessage());
                    return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0001") + ex.getLocalizedMessage())).build();
                }

                if (fer != null) {
                    SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.FINE, "FIDO-MSG-0046", fer.getResponse());
                    U2FAuthenticationResponse authResponse = (U2FAuthenticationResponse) fer.getResponse();
                    if (authResponse != null) {
                        //  Fetch the needed info from auth wsresponse return
                        int newCounter = authResponse.getCounter();
                        int userpresence = authResponse.getUsertouch();
//                String chall = authResponse.getChallenge();
//                try {
//                    KHhash = SKFSCommon.getDigest(chall, "SHA-256");
//                } catch (NoSuchAlgorithmException | NoSuchProviderException | UnsupportedEncodingException ex) {
//                    SKFSLogger.log(SKFSConstants.SKFE_LOGGER,Level.SEVERE, "FIDO-ERR-0001", " Error generating hash");
//                    return SKFSCommon.buildAuthenticateResponse("", logs, SKFSCommon.getMessageProperty("FIDO-ERR-0001") + " Error generating hash");
//                }
                        if (userpresence != SKFSConstants.USER_PRESENT_FLAG) {
                            //  Remove the sessionid from the sessionmap
                            skceMaps.getMapObj().remove(SKFSConstants.MAP_USER_SESSION_INFO, KHhash);
                            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.FINE, "FIDO-MSG-0023", "");

                            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0031", "");
                            return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0031"))).build();
                        }
                        //  Persist sign counter info & the user presence bytes to the database - TBD
                        FidoKeys key = null;
                        FidoKeysInfo fkinfo = (FidoKeysInfo) skceMaps.getMapObj().get(SKFSConstants.MAP_FIDO_KEYS, serverid + "-" + did + "-" + username + "-" + regkeyid);
                        if (fkinfo != null) {
                            key = fkinfo.getFk();
                        }
                        if (key == null) {
                            key = getkeybean.getByfkid(serverid, did, username, regkeyid);
                        }
                        if (key != null) {
                            int oldCounter = key.getCounter();
                            if (oldCounter != 0) {
                                if (newCounter <= oldCounter) {
                                    /**
                                     * Ideally should not happen. Neither does
                                     * U2F protocol specifies how to handle this
                                     * issue. So, just throw a warning msg in
                                     * the logs and proceed ahead.
                                     */
                                    //  Remove the user session from the sessionmap
                                    skceMaps.getMapObj().remove(SKFSConstants.MAP_USER_SESSION_INFO, KHhash);
                                    SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.FINE, "FIDO-MSG-0023", "");

                                    SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0030", "");
                                    return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0030"))).build();
                                }
                            }
                            //  update the sign counter value in the database with the new counter value.
                            String jparesult = updatekeybean.execute(serverid, did, username, regkeyid, newCounter, modifyloc);
                            JsonObject jo;
                            try (JsonReader jr = Json.createReader(new StringReader(jparesult))) {
                                jo = jr.readObject();
                            }
                            Boolean status = jo.getBoolean(SKFSConstants.JSON_KEY_FIDOJPA_RETURN_STATUS);
                            if (status) {
                                SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.FINE, "FIDO-MSG-0027", "");
                            } else {
                                SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0026", " new value=" + newCounter);
                            }
                        }

                        //  Remove the sessionid from the sessionmap
                        skceMaps.getMapObj().remove(SKFSConstants.MAP_USER_SESSION_INFO, KHhash);
                        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.FINE, "FIDO-MSG-0023", " username=" + username);
                    } else {
                        //  Remove the sessionid from the sessionmap
                        skceMaps.getMapObj().remove(SKFSConstants.MAP_USER_SESSION_INFO, KHhash);
                        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.FINE, "FIDO-MSG-0023", "");

                        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0015", "");
                        return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0015") + "")).build();
                    }
                } else {
                    return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("Failed to process authorization response") + "")).build();
                }
                responseJSON = SKFSCommon.buildReturn("Successfully processed authorization response");
            } else {
                try {
                    responseJSON = FIDO2Authejb.execute(did, authentication.getPayload().getResponse().toString(), authentication.getPayload().getMetadata().toString(), "authentication", null ,null, agent, cip);
                } catch (IllegalArgumentException | SKIllegalArgumentException ex) {
                    return Response.status(Response.Status.BAD_REQUEST).entity(ex.getMessage()).build();
                }
            }

            // Build the output json object
            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.FINE, "FIDO-MSG-0038", "");
        } catch (SKFEException ex) {
            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0034", "");
            return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0034"))).build();
        }

        out = new Date();
        long rt = out.getTime() - in.getTime();
        //  5. Print output and Return
        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.INFO, "FIDO-MSG-0008", "[TXID=" + ID + ", START=" + in.getTime() + ", FINISH=" + out.getTime() + ", TTC=" + rt + "]" + "\nResponse = " + responseJSON);
        return Response.ok().entity(responseJSON).build();
    }

    @Override
    public Response authorize(Long did, AuthenticationRequest authentication) {

        Date in = new Date();
        Date out;
        long thId = Thread.currentThread().getId();
        String ID = thId + "-" + in.getTime();
        //  1. Receive request and print inputs
        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.INFO, "FIDO-MSG-0015", "[TXID=" + ID + "]"
                + "\n did=" + did
                + "\n protocol=" + authentication.getSVCInfo().getProtocol()
                + "\n response=" + authentication.getPayload().getResponse()
                + "\n metadata=" + authentication.getPayload().getMetadata());

        //  2. Input checks
        if (authentication.getPayload().getResponse() == null || authentication.getPayload().getResponse().isEmpty()) {
            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0010", "");
            return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0010"))).build();
        }

        if (authentication.getPayload().getMetadata() == null || authentication.getPayload().getMetadata().isEmpty()) {
            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0017", "");
            return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0017"))).build();
        }

        //  4. Finish authentication
        String responseJSON;
        try {

            if (authentication.getSVCInfo().getProtocol().equalsIgnoreCase(SKFSConstants.FIDO_PROTOCOL_VERSION_U2F_V2)) {
                return Response.status(Response.Status.NOT_IMPLEMENTED).entity("U2F not being implemeted").build();
            } else {
                try {
                    responseJSON = FIDO2Authejb.execute(did, authentication.getPayload().getResponse().toString(), authentication.getPayload().getMetadata().toString(), "authorization",
                            authentication.getPayload().getTxid(), authentication.getPayload().getTxpayload(), "", "");
                } catch (IllegalArgumentException | SKIllegalArgumentException ex) {
                    return Response.status(Response.Status.BAD_REQUEST).entity(ex.getMessage()).build();
                }
            }
            // Build the output json object
            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.FINE, "FIDO-MSG-0038", "");
        } catch (Exception ex) {
            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0034", "");
            return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0034"))).build();
        }

        out = new Date();
        long rt = out.getTime() - in.getTime();
        //  5. Print output and Return
        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.INFO, "FIDO-MSG-0016", "[TXID=" + ID + ", START=" + in.getTime() + ", FINISH=" + out.getTime() + ", TTC=" + rt + "]" + "\nResponse = " + responseJSON);
//        String authzresponse = (String) applianceCommon.getJsonValue(responseJSON, SKFSConstants.JSON_KEY_SERVLET_RETURN_RESPONSE, "String");
//        JsonObject txdetail = (JsonObject) applianceCommon.getJsonValue(responseJSON, SKFSConstants.TX_DETAIL, "JsonObject");
//         JsonObjectBuilder job = Json.createObjectBuilder();
//         job.add(SKFSConstants.TX_DETAIL, txdetail);
//         job.add(SKFSConstants.JSON_KEY_SERVLET_RETURN_RESPONSE, authzresponse);
//         job.add(SKFSConstants.TX_AUTHORIZATION, authentication.getPayload().getResponse());
        return Response.ok().entity(responseJSON).build();
    }

    /*
     ************************************************************************
     *        888                                    d8b          888
     *        888                                    Y8P          888
     *        888                                                 888
     *    .d88888  .d88b.  888d888  .d88b.   .d88b.  888 .d8888b  888888  .d88b.  888d888
     *   d88" 888 d8P  Y8b 888P"   d8P  Y8b d88P"88b 888 88K      888    d8P  Y8b 888P"
     *   888  888 88888888 888     88888888 888  888 888 "Y8888b. 888    88888888 888
     *   Y88b 888 Y8b.     888     Y8b.     Y88b 888 888      X88 Y88b.  Y8b.     888
     *    "Y88888  "Y8888  888      "Y8888   "Y88888 888  88888P'  "Y888  "Y8888  888
     *                                           888
     *                                      Y8b d88P
     *                                      "Y88P"
     *
     ************************************************************************
     */
    /**
     * Method that performs de-registration process in FIDO U2F protocol. The
     * protocol as such does not specify any de-registration process. So, this
     * method just removes the user registered fido authenticator information
     * from the persistent storage.
     *
     * If the user has registered multiple fido authenticators, to identify
     * which key has to be deleted, there is a random id to be passed. This
     * random id for every registered fido authenticator can be obtained by
     * making the getkeysinfo call, which will return an array of registered key
     * metadata, each entry mapped to a random id. These random ids have a 'ttl
     * (time-to-live)' associated with them. This information is also sent back
     * with the key metadata during getkeysinfo call. The client applications
     * have to cache these random ids if they wish to de-register keys.
     *
     * @param did - FIDO domain id
     * @param keyid - Identifier for this key
     *
     * @return - A Json in String format. The Json will have 3 key-value pairs;
     * 1. 'Response' : String, with a simple message telling if the process was
     * successful or not. 2. 'Message' : Empty string since there is no
     * cryptographic work involved in de-registration 3. 'Error' : String, with
     * error message incase something went wrong. Will be empty if successful.
     */
    @Override
    public Response deregister(Long did, String keyid) {

        Date in = new Date();
        Date out;
        long thId = Thread.currentThread().getId();
        String ID = thId + "-" + in.getTime();
        //  1. Receive request and print inputs
        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.INFO, "FIDO-MSG-0009", "[TXID=" + ID + "]"
                + "\n did=" + did
                + "\n keyid=" + keyid);

        if (keyid == null || keyid.trim().isEmpty()) {
            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0020", " Missing 'keyid'");
            return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0020") + " Missing 'keyid'")).build();
        }

        //  5. handover the job to an ejb
        String responseJSON;
        SKCEReturnObject skcero = u2fderegbean.execute(did, keyid);
        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.FINE, "FIDO-MSG-0046", skcero);
        if (skcero.getErrorkey() != null) {
            responseJSON = SKFSCommon.buildReturn(skcero.getErrormsg());
            return Response.status(Response.Status.BAD_REQUEST).entity(responseJSON).build();
        } else {
            // Build the output
            String response = "Successfully deleted user registered security key";
            responseJSON = SKFSCommon.buildReturn(response);
            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.FINE, "FIDO-MSG-0039", "");
        }

        out = new Date();
        long rt = out.getTime() - in.getTime();
        //  6. Print output and Return
        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.INFO, "FIDO-MSG-0010", "[TXID=" + ID + ", START=" + in.getTime() + ", FINISH=" + out.getTime() + ", TTC=" + rt + "]" + "\nResponse" + responseJSON);
        return Response.ok().entity(responseJSON).build();
    }

    /**
     * Method that brings a specific user registered key stored in the
     * persistent storage into 'ACTIVE' status. The protocol as such does not
     * specify any activation process. So, this method just changes the user
     * registered fido authenticator information in the persistent storage to
     * bear an 'ACTIVE' status so that it could be used for fido-authentication.
     *
     * Since the user could have registered multiple fido authenticators, to
     * identify which key has to be activated, there is a random id to be
     * passed. This random id for every registered fido authenticator can be
     * obtained by making the getkeysinfo call, which will return an array of
     * registered key metadata, each entry mapped to a random id. These random
     * ids have a 'ttl (time-to-live)' associated with them. This information is
     * also sent back with the key metadata during getkeysinfo call. The client
     * applications have to cache these random ids if they wish to de-activate /
     * activate / de-register keys.
     *
     * @param did - FIDO domain id
     * @param keyid U2F protocol version to comply with.
     * @param fidokey - A stringified json with activate request and metadata
     * embedded into it.
     *
     * Example: { "request": { "username": "...", "randomid": "..." },
     * "metadata": { "version": "1.0", "modify_location": "Sunnyvale, CA" } }
     *
     * @return - A Json in String format. The Json will have 3 key-value pairs;
     * 1. 'Response' : String, with a simple message telling if the process was
     * successful or not. 2. 'Message' : Empty string since there is no
     * cryptographic work involved in activation 3. 'Error' : String, with error
     * message incase something went wrong. Will be empty if successful.
     */
    @Override
    public Response patchfidokey(Long did, String keyid, UpdateFidoKeyRequest fidokey) {

        Date in = new Date();
        Date out;
        long thId = Thread.currentThread().getId();
        String ID = thId + "-" + in.getTime();
        //  1. Receive request and print inputs
        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.INFO, SKFSCommon.getMessageProperty("FIDO-MSG-0019"), "[TXID=" + ID + "]"
                + "\n did=" + did
                + "\n keyid=" + keyid
                + "\n fidokey=" + fidokey.toString());

        //  2. Input checks
        if (keyid == null || keyid.isEmpty()) {
            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0002", " keyid");
            return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0002") + " keyid")).build();
        }

        //  6. handover job to an ejb
        String responseJSON;
        SKCEReturnObject skcero = u2factbean.execute(did, keyid, fidokey);
        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.FINE, "FIDO-MSG-0046", skcero);
        if (skcero.getErrorkey() != null) {
            responseJSON = SKFSCommon.buildReturn(skcero.getErrormsg());
            return Response.status(Response.Status.BAD_REQUEST).entity(responseJSON).build();
        } else {
            // Build the output
            String response = "Successfully updated user registered security key";
            responseJSON = SKFSCommon.buildReturn(response);
            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.FINE, "FIDO-MSG-0052", "");
        }

        out = new Date();
        long rt = out.getTime() - in.getTime();
        //  7. Print output and Return
        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.INFO, "FIDO-MSG-0020", "[TXID=" + ID + ", START=" + in.getTime() + ", FINISH=" + out.getTime() + ", TTC=" + rt + "]" + "\nResponse" + responseJSON);
        return Response.ok().entity(responseJSON).build();
    }

    /**
     * Method that returns back the metadata about registered fido
     * authenticators for the given user.
     *
     * If the user has registered multiple fido authenticators, this method will
     * return an array of registered key metadata, each entry mapped to a random
     * id. These random ids have a 'ttl (time-to-live)' associated with them.
     * The client applications have to cache these random ids if they wish to
     * de-register keys.
     *
     * @param did - FIDO domain id
     * @param username - String username to search keys for
     *
     * @return - A Json in String format. The Json will have 3 key-value pairs;
     * 1. 'Response' : A Json array, each entry signifying metadata of a key
     * registered; Metadata includes randomid and its time-to-live, creation and
     * modify location and time info etc., 2. 'Message' : Empty string since
     * there is no cryptographic work involved in this process. 3. 'Error' :
     * String, with error message incase something went wrong. Will be empty if
     * successful.
     */
    @Override
    public Response getkeysinfo(Long did, String username) {

        Date in = new Date();
        Date out;
        long thId = Thread.currentThread().getId();
        String ID = thId + "-" + in.getTime();
        //  1. Receive request and print inputs
        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.INFO, "FIDO-MSG-0011", "[TXID=" + ID + "]"
                + "\n did=" + did
                + "\n username=" + username);

        //  2. Input checks
        if (username == null || username.isEmpty()) {
            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.SEVERE, "FIDO-ERR-0002", " username");
            return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(SKFSCommon.getMessageProperty("FIDO-ERR-0002") + " username")).build();
        }

        //  3. Hand over the job to an ejb.
        String responseJSON;
        SKCEReturnObject skcero = u2fgetkeysbean.execute(did, username);
        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.FINE, "FIDO-MSG-0046", skcero);
        if (skcero.getErrorkey() != null) {
            return Response.status(Response.Status.BAD_REQUEST).entity(SKFSCommon.buildReturn(skcero.getErrormsg())).build();
        } else {
            // Build the output
            String keysJsonString = (String) skcero.getReturnval();
            if (keysJsonString == null) {
                return Response.status(Response.Status.NOT_FOUND).build();
            }
            JsonObject keysJsonObj;
            try (JsonReader jr = Json.createReader(new StringReader(keysJsonString))) {
                keysJsonObj = jr.readObject();
            }

            responseJSON = Json.createObjectBuilder()
                    .add(SKFSConstants.JSON_KEY_SERVLET_RETURN_RESPONSE, keysJsonObj)
                    .build().toString();
            SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.FINE, "FIDO-MSG-0040", "");
        }

        out = new Date();
        long rt = out.getTime() - in.getTime();
        //  4. Print output and Return
        SKFSLogger.log(SKFSConstants.SKFE_LOGGER, Level.INFO, "FIDO-MSG-0012", "[TXID=" + ID + ", START=" + in.getTime() + ", FINISH=" + out.getTime() + ", TTC=" + rt + "]" + "\nResponse" + responseJSON);
        return Response.ok().entity(responseJSON).build();
    }

    private String decryptKH(String token) {
        String decryptedToken = "";
        try {
            decryptedToken = CryptoUtil.decryptAES(token);
        } catch (Exception e) {
            log.severe("Could not decrypt");
        }

        return decryptedToken;
    }
}
