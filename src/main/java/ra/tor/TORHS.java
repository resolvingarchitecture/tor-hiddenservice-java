package ra.tor;

import ra.common.content.JSON;

import java.io.File;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

public class TORHS extends JSON {
    Integer virtualPort;
    Integer targetPort;
    String serviceId;
    String webDir;
    String privateKey;

    public TORHS() {}

    public TORHS(String serviceId, String privateKey) {
        this.serviceId = serviceId;
        this.privateKey = privateKey;
    }

    void setPrivateKey(String privateKey) throws NoSuchAlgorithmException {
        if (privateKey.startsWith("-----BEGIN")) // we reused a key
            this.privateKey = privateKey;
        else {
            String type = null;
            if (privateKey.startsWith(TORAlgorithms.RSA1024))
                type = "RSA";
            else if (privateKey.startsWith(TORAlgorithms.ED25519V3))
                type = "OPENSSH";
            else
                throw new NoSuchAlgorithmException(type);
            this.privateKey = "-----BEGIN " + type + " PRIVATE KEY-----\n"
                    + privateKey.substring(privateKey.indexOf(":") + 1) + "\n-----END " + type
                    + " PRIVATE KEY-----";
        }
    }

    @Override
    public Map<String, Object> toMap() {
        Map<String,Object> m = super.toMap();
        if(virtualPort!=null) m.put("virtualPort", virtualPort);
        if(targetPort!=null) m.put("targetPort", targetPort);
        if(serviceId!=null) m.put("serviceId", serviceId);
        if(webDir!=null) m.put("webDir", webDir);
        if(privateKey!=null) m.put("privateKey", privateKey);
        return m;
    }

    @Override
    public void fromMap(Map<String, Object> m) {
        super.fromMap(m);
        if(m.get("virtualPort")!=null) virtualPort = Integer.parseInt((String)m.get("virtualPort"));
        if(m.get("targetPort")!=null) targetPort = Integer.parseInt((String)m.get("targetPort"));
        if(m.get("serviceId")!=null) serviceId = (String)m.get("serviceId");
        if(m.get("webDir")!=null) webDir = (String)m.get("webDir");
        if(m.get("privateKey")!=null) privateKey = (String)m.get("privateKey");
    }
}
