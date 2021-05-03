package session;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.util.Date;

@Getter
@Setter
public class UserSessionInfo implements Serializable {

    private static final long serialVersionUID = 1L;
    private String username = null;
    private String displayName = null;
    private String rpName = null;
    private String nonce = null;
    private String initnonce = null;
    private Long txtimestamp = null;
    private String txpayload = null;
    private String txid = null;
    private String userId = null;
    private String sessiontype = null;
    private Date creationdate = null;
    private String userPublicKey = null;
    //fido key id
    private long fkid = 0;
    //server id where the key was originally registered
    private Short skid = 0;
    //server id where the prereg/preauth has been originated
    private Short sid = 0;
    private String sessionid = null;

    private String userIcon = null;
    private String userVerificationReq = null;
    private String attestationPreferance = null;
    private String policyMapKey = null;

    private String mapkey;

    /**
     * Constructor of this class.
     *
     * @param username - name of the user associated with this session
     * @param nonce - nonce generated for session (registration or auth)
     * @param sessiontype - type of session (register or auth)
     * @param userPublicKey - use public key
     * @param sessionID
     */
    public UserSessionInfo(String username, String nonce, SessionType sessiontype, String userPublicKey, String sessionID) {
        this.username = username;
        this.nonce = nonce;
        this.sessiontype = sessiontype.getLabel();
        this.creationdate = new Date();
        this.userPublicKey = userPublicKey;
        this.sessionid = sessionID;
    }

    public UserSessionInfo(){
        this.creationdate = new Date();
    }

    public Date getCreationdate() {
        if(creationdate == null){
            return null;
        }
        return new Date(creationdate.getTime());
    }

    public void setCreationdate(Date creationdate) {
        if(creationdate == null){
            this.creationdate = null;
        }else{
            this.creationdate = new Date(creationdate.getTime());
        }
    }

    public long getSessionAge() {
        Date rightnow = new Date();
        long age = (rightnow.getTime() / 1000) - (creationdate.getTime() / 1000);
        return age;
    }

    @Override
    public String toString() {
        return    "\n    username       = " + this.username
                + "\n    challenge      = " + this.nonce
                + "\n    sessiontype    = " + this.sessiontype
                + "\n    sessioni       = " + this.sessionid
                + "\n    UPK            = " + this.userPublicKey
                + "\n    age            = " + getSessionAge() + " seconds"
                + "\n    userId         = " + this.userId
                + "\n    userIcon       = " + this.userIcon
                + "\n    policyMapKey   = " + this.policyMapKey;
    }
}

