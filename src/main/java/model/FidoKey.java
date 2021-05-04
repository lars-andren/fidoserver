package model;

import crypto.CryptoUtil;
import lombok.extern.java.Log;

import javax.json.Json;
import javax.json.JsonObjectBuilder;
import javax.persistence.*;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

@Log
@Entity
@NamedQueries({
        @NamedQuery(name = "FidoKey.findAll", query = "SELECT f FROM FidoKey f"),
        @NamedQuery(name = "FidoKey.findByUserid", query = "SELECT f FROM FidoKey f WHERE f.userid = :userid"),
        @NamedQuery(name = "FidoKey.findByKeyhandle", query = "SELECT f FROM FidoKey f WHERE f.keyhandle = :keyhandle"),
        @NamedQuery(name = "FidoKey.findByPublickey", query = "SELECT f FROM FidoKey f WHERE f.publickey = :publickey"),
        @NamedQuery(name = "FidoKey.findByTransports", query = "SELECT f FROM FidoKey f WHERE f.transports = :transports"),
        @NamedQuery(name = "FidoKey.findByAttsid", query = "SELECT f FROM FidoKey f WHERE f.attsid = :attsid"),
        @NamedQuery(name = "FidoKey.findByAttcid", query = "SELECT f FROM FidoKey f WHERE f.attcid = :attcid"),
        @NamedQuery(name = "FidoKey.findByCounter", query = "SELECT f FROM FidoKey f WHERE f.counter = :counter"),
        @NamedQuery(name = "FidoKey.findByAppid", query = "SELECT f FROM FidoKey f WHERE f.appid = :appid"),
        @NamedQuery(name = "FidoKey.findByIcpid", query = "SELECT f FROM FidoKey f WHERE f.icpid = :icpid"),
        @NamedQuery(name = "FidoKey.findByFidoVersion", query = "SELECT f FROM FidoKey f WHERE f.fidoVersion = :fidoVersion"),
        @NamedQuery(name = "FidoKey.findByFidoProtocol", query = "SELECT f FROM FidoKey f WHERE f.fidoProtocol = :fidoProtocol"),
        @NamedQuery(name = "FidoKey.findByAaguid", query = "SELECT f FROM FidoKey f WHERE f.aaguid = :aaguid"),
        @NamedQuery(name = "FidoKey.findByRegistrationSettingsVersion", query = "SELECT f FROM FidoKey f WHERE f.registrationSettingsVersion = :registrationSettingsVersion"),
        @NamedQuery(name = "FidoKey.findByCreateDate", query = "SELECT f FROM FidoKey f WHERE f.createDate = :createDate"),
        @NamedQuery(name = "FidoKey.findByCreateLocation", query = "SELECT f FROM FidoKey f WHERE f.createLocation = :createLocation"),
        @NamedQuery(name = "FidoKey.findByModifyDate", query = "SELECT f FROM FidoKey f WHERE f.modifyDate = :modifyDate"),
        @NamedQuery(name = "FidoKey.findByModifyLocation", query = "SELECT f FROM FidoKey f WHERE f.modifyLocation = :modifyLocation"),
        @NamedQuery(name = "FidoKey.findByStatus", query = "SELECT f FROM FidoKey f WHERE f.status = :status"),
        @NamedQuery(name = "FidoKey.findBySignatureKeytype", query = "SELECT f FROM FidoKey f WHERE f.signatureKeytype = :signatureKeytype"),
        @NamedQuery(name = "FidoKey.findBySignature", query = "SELECT f FROM FidoKey f WHERE f.signature = :signature")})

public class FidoKey implements Serializable {

    private long autoId;

    private static final long serialVersionUID = 1L;

    private String username;

    private long fkid;

    private String appid;

    private String icpid;

    private String userid;

    private String keyhandle;

    private String publickey;

    private Short transports;

    private Short attsid;

    private Integer attcid;

    private int counter;

    private String fidoVersion;

    private String fidoProtocol;

    private String aaguid;

    @Lob
    private String registrationSettings;

    private Integer registrationSettingsVersion;

    @Temporal(TemporalType.TIMESTAMP)
    private Date createDate;

    private String createLocation;

    @Temporal(TemporalType.TIMESTAMP)
    private Date modifyDate;

    private String modifyLocation;

    private String status;

    private String signatureKeytype;

    private String signature;

    @Transient
    private String id;

    public FidoKey() { }

    public FidoKey(String keyhandle, int counter, Date createDate, String createLocation, String status, String signatureKeytype) {
        this.keyhandle = keyhandle;
        this.counter = counter;
        if(createDate !=null){
            this.createDate = new Date(createDate.getTime());
        }else{
            this.createDate =null;
        }
        this.createLocation = createLocation;
        this.status = status;
        this.signatureKeytype = signatureKeytype;
    }

    public String getUserid() {
        return userid;
    }

    public void setUserid(String userid) {
        this.userid = userid;
    }

    public String getAppid() { return this.appid; }

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    public long getAutoId() { return autoId; }

    public void setAutoId(long autoId) { this.autoId = autoId; }

    public String getKeyhandle() {
        return keyhandle;
    }

    public void setKeyhandle(String keyhandle) {
        String keyhandletoken = keyhandle;
        try {
            keyhandletoken = CryptoUtil.encryptAES(icpid + appid + keyhandle);
        } catch (Exception e) {
            log.severe("Error when encrypting keyhandle: " + e.getMessage());
        }

        this.keyhandle = keyhandletoken;
    }

    public String getPublickey() { return publickey; }

    public void setPublickey(String publickey) { this.publickey = publickey; }

    public Short getTransports() { return transports; }

    public void setTransports(Short transports) { this.transports = transports; }

    public Short getAttsid() { return attsid; }

    public void setAttsid(Short attsid) { this.attsid = attsid; }

    public Integer getAttcid() { return attcid; }

    public void setAttcid(Integer attcid) { this.attcid = attcid; }

    public int getCounter() {
        return counter;
    }

    public void setCounter(int counter) {
        this.counter = counter;
    }

    public String getFidoVersion() {
        return fidoVersion;
    }

    public void setFidoVersion(String fidoVersion) {
        this.fidoVersion = fidoVersion;
    }

    public String getFidoProtocol() {
        return fidoProtocol;
    }

    public void setFidoProtocol(String fidoProtocol) {
        this.fidoProtocol = fidoProtocol;
    }

    public String getAaguid() {
        return aaguid;
    }

    public void setAaguid(String aaguid) {
        this.aaguid = aaguid;
    }

    public String getRegistrationSettings() {
        return registrationSettings;
    }

    public void setRegistrationSettings(String registrationSettings) {
        this.registrationSettings = registrationSettings;
    }

    public Integer getRegistrationSettingsVersion() {
        return registrationSettingsVersion;
    }

    public void setRegistrationSettingsVersion(Integer registrationSettingsVersion) {
        this.registrationSettingsVersion = registrationSettingsVersion;
    }

    public Date getCreateDate() {
        if (createDate ==null) {
            return null;
        }
        return new Date(createDate.getTime());
    }

    public void setCreateDate(Date createDate) {
        if(createDate == null){
            this.createDate = null;
        }else{
            this.createDate = new Date(createDate.getTime());
        }
    }

    public String getCreateLocation() {
        return createLocation;
    }

    public void setCreateLocation(String createLocation) {
        this.createLocation = createLocation;
    }

    public Date getModifyDate() {
        if (modifyDate ==null) {
            return null;
        }
        return new Date(modifyDate.getTime());
    }

    public void setModifyDate(Date modifyDate) {
        if(modifyDate == null){
            this.modifyDate = null;
        }else{
            this.modifyDate = new Date(modifyDate.getTime());
        }
    }

    public String getModifyLocation() {
        return modifyLocation;
    }

    public void setModifyLocation(String modifyLocation) {
        this.modifyLocation = modifyLocation;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getSignatureKeytype() {
        return signatureKeytype;
    }

    public void setSignatureKeytype(String signatureKeytype) {
        this.signatureKeytype = signatureKeytype;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getId() {
        return id;
    }

    public long getFkid() {
        return this.fkid;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUsername() {
        return this.username;
    }

    public String toJsonObject(){
        JsonObjectBuilder job = Json.createObjectBuilder();
        job.add("fkid", this.getFkid());
        job.add("username", this.getUsername());
        if (this.userid != null) {
            job.add("userid", this.getUserid());
        }
        if (this.keyhandle != null) {
            job.add("keyhandle", this.getKeyhandle());
        }
        if (this.publickey != null) {
            job.add("publickey", this.getPublickey());
        }
        if (this.transports != null) {
            job.add("transports", this.getTransports());
        }
        if (this.attsid != null) {
            job.add("attsid", this.getAttsid());
        }
        if (this.attcid != null) {
            job.add("attcid", this.getAttsid());
        }
        if (this.fidoVersion != null) {
            job.add("fidoVersion", this.getFidoVersion());
        }
        if (this.fidoProtocol != null) {
            job.add("fidoProtocol", this.getFidoProtocol());
        }
        if (this.aaguid != null) {
            job.add("aaguid", this.getAaguid());
        }
        if (this.registrationSettings != null) {
            job.add("registrationSettings", this.getRegistrationSettings());
        }
        if (this.registrationSettingsVersion != null) {
            job.add("registrationSettingsVersion", this.getRegistrationSettingsVersion());
        }

        job.add("status", this.getStatus());

        String res = job.build().toString();
        return res;
    }
}
