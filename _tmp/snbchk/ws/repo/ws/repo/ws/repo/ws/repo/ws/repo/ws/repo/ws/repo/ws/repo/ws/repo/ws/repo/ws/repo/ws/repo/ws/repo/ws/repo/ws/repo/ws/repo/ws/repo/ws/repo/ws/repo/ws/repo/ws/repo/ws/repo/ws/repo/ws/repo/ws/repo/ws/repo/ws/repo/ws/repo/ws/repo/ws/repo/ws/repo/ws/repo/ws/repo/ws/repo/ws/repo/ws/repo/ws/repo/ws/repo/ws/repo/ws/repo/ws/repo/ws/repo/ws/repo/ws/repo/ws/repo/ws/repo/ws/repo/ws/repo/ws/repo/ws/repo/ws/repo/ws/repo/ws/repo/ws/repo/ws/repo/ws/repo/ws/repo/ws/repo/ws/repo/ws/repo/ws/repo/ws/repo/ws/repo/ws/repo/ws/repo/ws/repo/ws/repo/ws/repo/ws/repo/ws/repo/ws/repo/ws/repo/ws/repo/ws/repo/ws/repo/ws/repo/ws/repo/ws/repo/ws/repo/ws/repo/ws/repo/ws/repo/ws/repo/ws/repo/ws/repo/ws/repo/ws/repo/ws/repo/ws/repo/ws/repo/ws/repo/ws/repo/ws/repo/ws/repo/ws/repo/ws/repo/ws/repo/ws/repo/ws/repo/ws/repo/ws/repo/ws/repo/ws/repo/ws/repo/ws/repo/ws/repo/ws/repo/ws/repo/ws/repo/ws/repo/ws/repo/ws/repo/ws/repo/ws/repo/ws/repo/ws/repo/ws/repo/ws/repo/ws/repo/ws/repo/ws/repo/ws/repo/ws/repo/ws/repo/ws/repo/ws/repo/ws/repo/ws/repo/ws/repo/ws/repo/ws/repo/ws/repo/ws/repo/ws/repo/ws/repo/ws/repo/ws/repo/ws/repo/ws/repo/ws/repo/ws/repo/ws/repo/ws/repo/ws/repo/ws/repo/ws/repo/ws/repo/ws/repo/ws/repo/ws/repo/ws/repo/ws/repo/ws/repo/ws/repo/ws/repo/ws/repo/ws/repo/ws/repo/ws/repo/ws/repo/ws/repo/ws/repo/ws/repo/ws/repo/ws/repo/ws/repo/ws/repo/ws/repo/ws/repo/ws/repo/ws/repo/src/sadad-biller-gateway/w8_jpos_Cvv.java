import org.jpos.security.*;
public class CvvCheck {
    boolean verify(SMAdapter sm, String pan, String exp, String svc, String cvv, SecureDESKey cvk) throws SMException {
        return sm.verifyCVV(pan, cvk, cvv, exp, svc);
    }
}
