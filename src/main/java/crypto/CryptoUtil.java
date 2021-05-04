package crypto;

import common.Common;
import common.Constants;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

@Component("CrytoUtil")
public class CryptoUtil {

    private static final String ALGORITHM_AES = "AES/CBC/PKCS7Padding";
    private static final SecretKey AES_KEY = new SecretKeySpec(Common.getProperty("crypto.property.aeskey").getBytes(), "AES");

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final IvParameterSpec DEFAULT_IV = new IvParameterSpec(Strings.toByteArray("CB442FFF45298BC2"));

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

    public static String encryptAES(String data) throws Exception {

        byte[] base64data = Base64.getEncoder().encode(data.getBytes());

        Cipher cipher = Cipher.getInstance(ALGORITHM_AES);
        cipher.init(Cipher.ENCRYPT_MODE, AES_KEY, DEFAULT_IV);
        byte[] encryptedBytes = cipher.doFinal(base64data);
        String base64String = Base64.getEncoder().encodeToString(encryptedBytes);

        return base64String;
    }

    public static String decryptAES(String data) throws Exception {

        byte[] encryptedData = Base64.getDecoder().decode(data);

        Cipher cipher = Cipher.getInstance(ALGORITHM_AES);
        cipher.init(Cipher.DECRYPT_MODE, AES_KEY, DEFAULT_IV);
        byte[] decryptedBytes = cipher.doFinal(encryptedData);
        String decryptedString = new String(decryptedBytes);

        return decryptedString;
    }
}
