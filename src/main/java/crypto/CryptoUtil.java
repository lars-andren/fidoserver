package crypto;

import common.Constants;

import java.security.SecureRandom;
import java.util.Base64;

public class CryptoUtil {

    public static String getRandom(int size) {

        if (size > Constants.MAX_RANDOM_NUMBER_SIZE_BITS / 8) {
            size = Constants.MAX_RANDOM_NUMBER_SIZE_BITS / 8;
        }

        SecureRandom random = new SecureRandom();
        byte seed[] = new byte[20];
        random.nextBytes(seed);

        SecureRandom sr = new SecureRandom(seed);
        byte[] randomBytes = new byte[size];
        sr.nextBytes(randomBytes);

        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
}
