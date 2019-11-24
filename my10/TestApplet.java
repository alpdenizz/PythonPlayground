package appcrypto;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

// took 5.5 hours (please specify here how much time your solution required)


public class TestApplet extends Applet {
	
	private KeyPair keypair;
	private RSAPublicKey pub;
	private Cipher rsa;
	private boolean isGenerated = false;
	
	public static void install(byte[] ba, short offset, byte len) {
		(new TestApplet()).register();
	}
	
	public void process(APDU apdu) {
		byte[] buf = apdu.getBuffer();
		
		switch (buf[ISO7816.OFFSET_INS]) {
			case (0x02):
				if (!isGenerated && buf[ISO7816.OFFSET_P1] == 0x08) {
					isGenerated = true;
					keypair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
					keypair.genKeyPair();
				}		
				else if (!isGenerated && buf[ISO7816.OFFSET_P1] == 0x04) {
					isGenerated = true;
					keypair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
					keypair.genKeyPair();
				}
				return;
			case (0x04):
				// send r
				pub = (RSAPublicKey) keypair.getPublic();
				short r = pub.getExponent(buf, (short)0);
				apdu.setOutgoingAndSend((short)0, r);
				return;
			case (0x06):
				// send n
				pub = (RSAPublicKey) keypair.getPublic();
				short n = pub.getModulus(buf, (short)0);
				apdu.setOutgoingAndSend((short)0, n);
				return;
			case (0x08):
				//decrypt ciphertext
				short len2 = (short)(buf[ISO7816.OFFSET_LC] & (short)0xff);
				apdu.setIncomingAndReceive();
				Util.arrayCopyNonAtomic(buf, (short)ISO7816.OFFSET_P1, buf, (short)ISO7816.OFFSET_P2, (short)2);
				rsa = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
				rsa.init(keypair.getPrivate(), Cipher.MODE_DECRYPT);
				short m = rsa.doFinal(buf, (short)ISO7816.OFFSET_P2, (short)(len2+2), buf, (short)0);
				apdu.setOutgoingAndSend((short)0, m);
				return;
		}
		ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);		
	}
}
