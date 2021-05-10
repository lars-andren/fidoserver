package dal;

import model.FidoKey;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

@Component("database")
public class Database {

    FidoKey fidoKey1;
    FidoKey fidoKey2;

    @PostConstruct
    public void setUp() {
        fidoKey1 = new FidoKey("keyhandle", 1, new Date(), "here", "ACTIVE", "signKeyType");
        fidoKey2 = new FidoKey("keyhandle", 1, new Date(), "here", "ACTIVE", "signKeyType");
    }

    public Collection<FidoKey> getByUsername(String icpId, String username) {
        return new ArrayList<>(Arrays.asList(fidoKey1, fidoKey2));
    }

    public Collection<FidoKey> getKeysByUsernameStatus(String icpId, String username, String status) {
        return new ArrayList<>(Arrays.asList(fidoKey1, fidoKey2));
    }
}
