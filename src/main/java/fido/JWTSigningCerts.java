/**
* Copyright StrongAuth, Inc. All Rights Reserved.
*
* Use of this source code is governed by the GNU Lesser General Public License v2.1
* The license can be found at https://github.com/StrongKey/fido2/blob/master/LICENSE
*/

package fido;

import com.strongkey.skfs.utilities.SKFSConstants;

import javax.json.JsonObject;

public class JWTSigningCerts {
    private final String dn;
    private final Integer certsPerServer;
    private JWTSigningCerts(String dn, Integer certsPerServer){
        this.dn = dn;
        this.certsPerServer = certsPerServer;
    }

    public String getDN() {
        return dn;
    }


    public Integer getCertsPerServer() {
        return certsPerServer;
    }

    public static JWTSigningCerts parse(JsonObject JWTJson) {

        return new JWTSigningCertsBuilder(
                JWTJson.getString(SKFSConstants.POLICY_JWT_SIGN_CERT_DN),
                JWTJson.getInt(SKFSConstants.POLICY_JWT_SIGN_CERT_COUNT)
        ).build();
    }

    public static class JWTSigningCertsBuilder{
        private final String builderDN;
        private final Integer builderCertsPerServer;

        public JWTSigningCertsBuilder(String dn, Integer certsPerServer){
            this.builderDN = dn;
            this.builderCertsPerServer= certsPerServer;
        }


        public JWTSigningCerts build(){
            return new JWTSigningCerts(builderDN, builderCertsPerServer);
        }
    }
}
