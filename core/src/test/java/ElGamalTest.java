import org.junit.Assert;
import org.junit.Test;
import org.zespol.core.ElGamal;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public class ElGamalTest {
    @Test
    public void basicTest() {
        ElGamal gamal = new ElGamal();
        List<BigInteger> params = gamal.generateParameters(2048);
        BigInteger privateKey = gamal.generatePrivateKey(params);
        List<BigInteger> publicKey = gamal.generatePublicKey(params, privateKey);
        String message = "Ala ma kota, a kot ma ale";
        String message1 = "Ala ma kota a kot ma ale";
        List<BigInteger> signature;
        boolean result1, result2;
        try {
            signature = gamal.sign(message.getBytes(StandardCharsets.UTF_8), privateKey, params);
            result1 = gamal.verify(message.getBytes(StandardCharsets.UTF_8), signature, publicKey);
            result2 = gamal.verify(message1.getBytes(StandardCharsets.UTF_8), signature, publicKey);
            Assert.assertTrue(result1);
            Assert.assertFalse(result2);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void pdfTest() {
        ElGamal gamal = new ElGamal();
        List<BigInteger> params = gamal.generateParameters(2048);
        BigInteger privateKey = gamal.generatePrivateKey(params);
        List<BigInteger> publicKey = gamal.generatePublicKey(params, privateKey);
        List<BigInteger> signature;
        boolean result1, result2;
        try (FileInputStream inputStream = new FileInputStream("./plik.pdf")) {
            byte[] message = inputStream.readAllBytes();
            signature = gamal.sign(message, privateKey, params);
            result1 = gamal.verify(message, signature, publicKey);
            message[0] = (byte) (message[0] + 1);
            result2 = gamal.verify(message, signature, publicKey);
            Assert.assertTrue(result1);
            Assert.assertFalse(result2);
        } catch (NoSuchAlgorithmException ignored) {} catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
