package sales.security;

import java.security.MessageDigest;

/**
 * Created by taras on 28.07.15.
 */
public class StringToMd5 {
    public static String getMd5(String original) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(original.getBytes());
        byte[] digets = md.digest();
        StringBuffer sb = new StringBuffer();
        for(byte b: digets) {
            sb.append(String.format("%02x", b & 0xff));
        }

        return sb.toString();
    }
}
