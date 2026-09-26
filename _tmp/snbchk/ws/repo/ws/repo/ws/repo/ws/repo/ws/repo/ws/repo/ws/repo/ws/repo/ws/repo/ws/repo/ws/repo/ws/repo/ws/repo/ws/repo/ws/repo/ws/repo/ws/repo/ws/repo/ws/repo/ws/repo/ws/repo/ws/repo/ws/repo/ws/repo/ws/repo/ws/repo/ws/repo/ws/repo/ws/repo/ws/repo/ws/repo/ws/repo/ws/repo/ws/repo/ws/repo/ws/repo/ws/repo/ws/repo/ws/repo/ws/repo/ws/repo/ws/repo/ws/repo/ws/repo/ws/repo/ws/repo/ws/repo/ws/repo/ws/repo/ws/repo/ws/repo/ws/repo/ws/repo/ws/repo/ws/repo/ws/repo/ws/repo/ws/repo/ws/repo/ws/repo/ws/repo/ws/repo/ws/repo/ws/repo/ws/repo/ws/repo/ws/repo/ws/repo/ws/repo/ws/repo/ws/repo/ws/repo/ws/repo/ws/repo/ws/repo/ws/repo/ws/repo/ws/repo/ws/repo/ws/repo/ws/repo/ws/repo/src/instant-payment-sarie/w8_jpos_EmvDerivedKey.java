import org.jpos.security.*;
public class Skd {
    byte[] derive(SMAdapter sm, SecureDESKey imk, String pan, String seq, byte[] atc) throws SMException {
        return sm.generateSM_MAC(MKDMethod.OPTION_A, SKDMethod.MCHIP, imk, pan, seq, atc, null, null);
    }
}
