import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;

public class Main {
    private static BigInteger p_prime, q_prime, N_a, L_euler, e_a, d_a, s_value, e_teacherKey, N_teacherKey, x_key, sig_x, h_c, expected_h_c, sig_c, h_inv, sig_h_inv;
    private static String[] teacherKey = {"2E76A0094D4CEE0AC516CA162973C895", "1985008F25A025097712D26B5A322982B6EBAFA5826B6EDA3B91F78B7BD63981382581218D33A9983E4E14D4B26113AA2A83BBCCFDE24310AEE3362B6100D06CC1EA429018A0FF3614C077F59DE55AADF449AF01E42ED6545127DC1A97954B89729249C6060BA4BD3A59490839072929C0304B2D7CBBA368AEBC4878A6F0DA3FE58CECDA638A506C723BDCBAB8C355F83C0839BF1457A3B6B89307D672BBF530C93F022E693116FE4A5703A665C6010B5192F6D1FAB64B5795876B2164C86ABD7650AEDAF5B6AFCAC0438437BB3BDF5399D80F8D9963B5414EAFBFA1AA2DD0D24988ACECA8D50047E5A78082295A987369A67D3E54FFB7996CBE2C5EAD794391"};
    private static BigInteger[] publicKey = new BigInteger[2];
    private static BigInteger[] privateKey = new BigInteger[2];

    private static String[] xSigPkHex = new String[4];

    private static String cTeacher = "C4F591A5D6DE78AC9D830BD5315EA0F5A109C661FFEFB40952686D3CC58E2BADF1C33BAD5B2617F79D9566A5CB92FCAE930704BC8A886387A496B9D7C505139291B1CA3597E819A4F0597D42020DBB2D570EF0C456A3B728A6E24B22C3B5936D";
    private static String sig_cTeacher = "0B31E6B97B8253E012B7F79EA8614031D82324782B77F4BD56CFB26432281D013E7F61B7C9ECB6BF92EDFD74AD276FC202FA489F68F1BCE8B1A8B6CEB85006FD39F2C2C6FABB82B46D58773C4F34D9A596D7FE4597E67CC79142ADE308D629B940D74364E7F71B39B4EA7C3006B1888C64389877B4FCF859D4D98657671BBD90F40ED38A5B4C4C5EBF5B351E22B4237AD7C57E13CF78EC0293CA290A064D5F1FAD7F9BD61F7CAED5F68145BA2FCA992F73DBA19AADAE884139E4068079F2A786950CC09D8A5798A54E580C7E4D4834C923F65D393A10FBB787BB4D81AFFD9DE019F78238DEC2099B708DFC45BD0710DBB801F6D6596FC429B3095E6A19AB8EA0";

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Parte 1

        // Gera os dois primos p e q
        p_prime = generatePrime(1024);
        q_prime = generatePrime(1024);

        // Calcula Na = p * q
        N_a = p_prime.multiply(q_prime);

        // Calcula L = (p-1).(q-1)
        L_euler = calcEulerFunction(p_prime, q_prime);

        // Encontra um e_a que seja primo relativo de L_euler
        findRelativePrime();

        // Calcula o inverso d_a de e_a em Z_L
        d_a = e_a.modInverse(L_euler);

        // Guarda os valores de pk_a e sk_a
        // pk_a = (e_a, N_a)
        publicKey[0] = e_a;
        publicKey[1] = N_a;
        // sk_a = (d_a, N_a)
        privateKey[0] = d_a;
        privateKey[1] = N_a;

        // Valor aleatório s_value de 128 bits
        s_value = generateRandomValue(128);

        // Calcula x = s^(e_teacherKey) mod N_(teacherKey)
        e_teacherKey = new BigInteger(teacherKey[0], 16);
        N_teacherKey = new BigInteger(teacherKey[1], 16);
        x_key = s_value.modPow(e_teacherKey, N_teacherKey);

        // Calcula sig_x = x_key^(d_a) mod N_a
        sig_x = x_key.modPow(d_a, N_a);

        // Enviar (x, sigx, pka) para o professor em hexadecimal
        xSigPkHex[0] = validateKey(x_key).toString(16);
        xSigPkHex[1] = validateKey(sig_x).toString(16);
        xSigPkHex[2] = validateKey(publicKey[0]).toString(16);
        xSigPkHex[3] = validateKey(publicKey[1]).toString(16);

        // Exibe o que será enviado
        System.out.println("(x, sig_x, pk_a):");
        System.out.println(xSigPkHex[0]);
        System.out.println(xSigPkHex[1]);
        System.out.println(xSigPkHex[2]);
        System.out.println(xSigPkHex[3]);

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Parte 2
        byte[] cTeacherBytes, iv, ciphertext, keyBytes, plaintextBytes, newIV, encrypted_m_inv, c_inv;
        String m_plaintext, m_inv, c_inv_hex, sig_h_inv_hex;

        // Calcula h_c = SHA-256(cTeacher)
        h_c = calcSHA256(cTeacher);

        // Calcula o h_c esperado (sig_cTeacher^(e_p) mod N_p)
        sig_c = new BigInteger(sig_cTeacher, 16);
        expected_h_c = sig_c.modPow(e_teacherKey, N_teacherKey);

//        if (h_c.equals(expected_h_c)) {
//
//        }

        // Transforma em array de bytes e separa IV do Ciphertext
        cTeacherBytes = hexToBytes(cTeacher);
        iv = Arrays.copyOfRange(cTeacherBytes, 0, 16);
        ciphertext = Arrays.copyOfRange(cTeacherBytes, 16, cTeacherBytes.length);
        keyBytes = s_value.toByteArray();

        // Decifra a mensagem
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        plaintextBytes = cipher.doFinal(ciphertext);

        // Converte a mensagem decifrada de bytes para string e inverte
        m_plaintext = new String(plaintextBytes, "UTF-8");
        m_inv = new StringBuilder(m_plaintext).reverse().toString();

        // Gera um IV aleatório
        newIV = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(newIV);

        // Cifra a mensagem invertida
        SecretKeySpec newKey = new SecretKeySpec(keyBytes, "AES");
        Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, newKey, new IvParameterSpec(newIV));
        encrypted_m_inv = encryptCipher.doFinal(m_inv.getBytes("UTF-8"));

        // Concatena IV e a mensagem cifrada
        c_inv = new byte[newIV.length + encrypted_m_inv.length];
        System.arraycopy(newIV, 0, c_inv, 0, newIV.length);
        System.arraycopy(encrypted_m_inv, 0, c_inv, newIV.length, encrypted_m_inv.length);

        // Converte c_inv para hexadecimal
        c_inv_hex = bytesToHex(c_inv);

        // Calcula h_inv = SHA-256(c_inv)
        h_inv = calcSHA256(c_inv_hex);

        // Calcula sig_h_inv = h_inv^(d_a) mod N_a
        sig_h_inv = h_inv.modPow(d_a, N_a);

        // Converte sig_h_inv para hexadecimal
        sig_h_inv_hex = sig_h_inv.toString(16);

        // Enviar (c_inv, sig_h_inv) para o professor em hexadecimal
        System.out.println("(c_inv, sig_h_inv):");
        System.out.println(c_inv_hex);
        System.out.println(sig_h_inv_hex);
    }

    // Gera um número primo de acordo com o número de bits
    private static BigInteger generatePrime(int bits) {
        SecureRandom random = new SecureRandom();
        return new BigInteger(bits, 100, random);
    }

    // Calcula a função de Euler φ(n) = (p-1) * (q-1)
    private static BigInteger calcEulerFunction(BigInteger p, BigInteger q) {
        return p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    }

    // Encontra um número que seja primo relativo de L_euler
    private static void findRelativePrime() {
        SecureRandom random = new SecureRandom();
        do {
            e_a = new BigInteger(128, random);
        } while (e_a.compareTo(BigInteger.ONE) <= 0 || e_a.compareTo(L_euler) >= 0 || !e_a.gcd(L_euler).equals(BigInteger.ONE));
    }

    // Valida a chave e adiciona byte 0 no início se necessário
    private static BigInteger validateKey(BigInteger key) {
        String hex = key.toString(16);
        if (hex.matches("^[89ABCDEF].*")) {
            return new BigInteger("00" + hex, 16);
        }
        return key;
    }

    // Gera um valor aleatório de acordo com o número de bits
    private static BigInteger generateRandomValue(int bits) {
        SecureRandom random = new SecureRandom();
        return new BigInteger(bits, random);
    }

    // Converte uma string hexadecimal para um array de bytes
    private static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    // Converte um array de bytes para uma string hexadecimal
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }

    private static BigInteger calcSHA256(String cHex) throws NoSuchAlgorithmException {
        // Converte a mensagem cifrada hexadecimal para bytes
        byte[] cBytes = hexToBytes(cHex);

        // Calcula o SHA-256
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(cBytes);

        // Converte o hash SHA-256 para BigInteger
        return new BigInteger(1, hashBytes);
    }
}
