
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
/*
 * This program executes the Diffie-Hellman key agreement protocol between
 * 4 parties: Alice, Bob, Carol and Pablo using a shared 2048-bit DH parameter.
 */
public class DHKeyAgreement4 {
    private DHKeyAgreement4() {}
    public static void main(String argv[]) throws Exception {
        // Alice creates her own DH key pair with 2048-bit key size
        System.out.println("ALICE: Generate DH keypair ...");
        KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
        aliceKpairGen.initialize(2048);
        KeyPair aliceKpair = aliceKpairGen.generateKeyPair();
        // This DH parameters can also be constructed by creating a
        // DHParameterSpec object using agreed-upon values
        DHParameterSpec dhParamShared = ((DHPublicKey)aliceKpair.getPublic()).getParams();
        // Bob creates his own DH key pair using the same params
        System.out.println("BOB: Generate DH keypair ...");
        KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
        bobKpairGen.initialize(dhParamShared);
        KeyPair bobKpair = bobKpairGen.generateKeyPair();
        // Carol creates her own DH key pair using the same params
        System.out.println("CAROL: Generate DH keypair ...");
        KeyPairGenerator carolKpairGen = KeyPairGenerator.getInstance("DH");
        carolKpairGen.initialize(dhParamShared);
        KeyPair carolKpair = carolKpairGen.generateKeyPair();
        //Pablo creates his own DH key pair using same params
        System.out.println("PABLO: Generate DH keypair ...");
        KeyPairGenerator pabloKpairGen = KeyPairGenerator.getInstance("DH");
        pabloKpairGen.initialize(dhParamShared);
        KeyPair pabloKpair = pabloKpairGen.generateKeyPair();
        // Alice initialize
        System.out.println("ALICE: Initialize ...");
        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
        aliceKeyAgree.init(aliceKpair.getPrivate());
        // Bob initialize
        System.out.println("BOB: Initialize ...");
        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
        bobKeyAgree.init(bobKpair.getPrivate());
        // Carol initialize
        System.out.println("CAROL: Initialize ...");
        KeyAgreement carolKeyAgree = KeyAgreement.getInstance("DH");
        carolKeyAgree.init(carolKpair.getPrivate());
        //pablo initialize
        System.out.println("PABLO: Initialize ...");
        KeyAgreement pabloKeyAgree = KeyAgreement.getInstance("DH");
        pabloKeyAgree.init(pabloKpair.getPrivate());

        //First phase - last = false
        //Alice computes gPA
        Key gPA = aliceKeyAgree.doPhase(pabloKpair.getPublic(), false);
        //Bob computes gAB
        Key gAB = bobKeyAgree.doPhase(aliceKpair.getPublic(),false);
        //Carol computes gBC
        Key gBC = carolKeyAgree.doPhase(bobKpair.getPublic(),false);
        //Pablo computes gCP
        Key gCP = pabloKeyAgree.doPhase(carolKpair.getPublic(), false);

        //Phase 2 - last = false
        //Alice computes gCPA
        Key gCPA = aliceKeyAgree.doPhase(gCP, false);
        //Bob computes gPAB
        Key gPAB = bobKeyAgree.doPhase(gPA, false);
        //Carol computes gABC
        Key gABC = carolKeyAgree.doPhase(gAB, false);
        //Pablo computes gBCP
        Key gBCP = pabloKeyAgree.doPhase(gBC, false);

        //Phase 3 - last = true
        //Alice computes gBCPA
        Key gBCPA = aliceKeyAgree.doPhase(gBCP, true);
        //Bob computes gCPAB
        Key gCPAB = bobKeyAgree.doPhase(gCPA,true );
        //Pablo computes gABCP
        Key gABCP = pabloKeyAgree.doPhase(gABC, true);
        //Carol computes gPABC
        Key gPABC = carolKeyAgree.doPhase(gPAB, true);

        // Alice, Bob, Carol abd Pablo compute their secrets
        byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
        System.out.println("Alice secret: " + toHexString(aliceSharedSecret));
        byte[] bobSharedSecret = bobKeyAgree.generateSecret();
        System.out.println("Bob secret: " + toHexString(bobSharedSecret));
        byte[] carolSharedSecret = carolKeyAgree.generateSecret();
        System.out.println("Carol secret: " + toHexString(carolSharedSecret));
        byte[] pabloSharedSecret = pabloKeyAgree.generateSecret();
        System.out.println("Pablo secret: " + toHexString(pabloSharedSecret));

        // Compare Alice and Bob
        if (!java.util.Arrays.equals(aliceSharedSecret, bobSharedSecret))
            throw new Exception("Alice and Bob differ");
        System.out.println("Alice and Bob are the same");
        // Compare Bob and Carol
        if (!java.util.Arrays.equals(bobSharedSecret, carolSharedSecret))
            throw new Exception("Bob and Carol differ");
        System.out.println("Bob and Carol are the same");
        //compare Carol and Pablo
        if (!java.util.Arrays.equals(pabloSharedSecret, carolSharedSecret))
            throw new Exception("Carol and Pablo differ");
        System.out.println("Carol and Pablo are the same");
    }
    /*
     * Converts a byte to hex digit and writes to the supplied buffer
     */
    private static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }
    /*
     * Converts a byte array to hex string
     */
    private static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();
        int len = block.length;
        for (int i = 0; i < len; i++) {
            byte2hex(block[i], buf);
            if (i < len-1) {
                buf.append(":");
            }
        }
        return buf.toString();
    }
}
