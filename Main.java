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

//**********************************************************************************************************************
//
//  Trabalho 2 - Segurança de Sistemas
//  Aluno: Cassiano Luis Flores Michel - 20204012-7
//
// Valores gerados e utilizados como exemplo para a implementação do trabalho:
//
//     s_value: 72862267910800375299092212796851321816
//           x: 192076a58fa51f9fb01f16e5812790fbc7d838649a88ad61034811338f41db7d3231cbc237dd674866d439eb71ed0dae1524de5d238c1c79bdfa7f770c69135285016c125760dbda5174b784155f1f1a57dbafa14ee328a5603e2ccd3fdedd81ac073dfc2b1c28ad8777b06d98ebc4313191f3415cebe2b6ba479a8ef22dcdff92277a7c55a59688548f27d74a291b98d747f819a8df0eab9dd3e6897edbfc4afaecf73f8a57df72f8ee9beed43dd9d160da8efbe51d24d726c89dc651f17f6429886e1e753f5cd9439b8a9750dc903d8bf8e3ae6b2045fc7ff82bc66e681a18d61397b8bbf1cee71abb01c8614e58a458931bfa54baa1d3653d51259d96c428
//       sig_x: 743eaa61ff0da0bf8d45730b2985c98db4eeae0dab50aae366deaa965e31a1eef90a5d24efa7fbedc2fec1d569b075b43ce34786b1d5d7c5d9fd292a3adc9f3ef9d89766049e14ea9c7be4c8deddd51d910eef1a1e2042bce0dfc4763eaae82b0c9164b4f95f3efae2e7b6f250ee200e2a00ac0e7ce1f284b03d5accf016a248967cdce488b0b140e6b386584afbc72af3c5b82f1f0807993d565cec07e9ff0fb9f65956d16007b4e9b4631eb82cc4f498552fe9c6333ef1c9bae2173507b40403ab3fff58b655aca471d4cff9a50d65cefe37b5b9341faf5a4aa3bccd848fa0333c98e126c7d27f6ef5a5dccecec0a3b5c2f89b069fa97fb6e949d7d1886fb3
//         e_a: 667b9292bac3c0da7840b1a533f026f1
//         N_a: 745af8c5f16e30981f958ddd57e56becae735a95c649afb057c54f24fadc8229e1035f7b5465a4198e184360c436c421ce8c9ead6dd2d4f47def120a2f04ce2c03b8d76cfb793511728c2cb48a11319ef3996180435f0e532f0034dcdedbd96f32a2e1b653ada46d63e465072d3294237a9785008b91fef18d71bda15a2ca23a40caa53e0bd4f368fda37767eea1039192f907dd047486ad673d72d1b56276470c4ed37c41384fa94ac48d173f9c3a65d421f63cde81e6ff85988331e947ac22a1ced3b6842e091d31babf761533c1fe0e17edf7df46d5e28e8b18c9721ed7a9057ac3afb104468ffe128448efeb15fc91c5878cf2a72ec2744dc5214f071d83
//         d_a: 5c8fe06236c99396256eb115cf50a13cd2813f2f6da1495ecfa037266cbc4fb82587e22fbd1e97f40f91ea034ccc75dc639c1f67a42041e5dc10447e9fe46a9d80f0361f5934daf28f25cc31423ab06fc810e179b59816d189dc68327edd32aac38216c11ab51f55863cc91aae6e74982ac281df5aae3c085173f482d317627b4794858e34f6b7f8376b34e48039db53f5530657997b8fbeaa5d3d97712adb28289a4f601d3d19ccbfa767a9b19decabc26d67d327326f5e8923db3e2889bf1d71ba7c5ade6303968331e8a33bb907258aa430975a961124464c344af72734ddfffc183cec0d790699726472acdd370844167c61498d5cbb5a704c66e42a3161
//       c_inv: e28217f20f22469194aba5f14a5954ac778bd0bf376b6294cd2416176d02ac411de4ad5162f6d2fd8677f7d978e0f3865a06246c48a6663d12200ad9e24fe18971f901f9e71334566d49ad0370ea4927db5572442b84ba5f90e07bd28f9ff250
//   sig_h_inv: 128438131717b074d936f2f8c2c3b92165b89829fb55a835002837eb5d09a2abe1927042cd393d362e8bae1c551438c5b40d6c94439630af56961df38750353bf8e074937ebb5cd56dc79142b232de8677609ce28a3cbe14d7cd488a4ddf59cb75cdef392115078668c6fe8b8742515e49d5c8e35e416d35d3332ec56593b452a6982a49b10c884565b49a91776dc5f68891cddc874f543dbd2a02c1c7922b5b303eb8543f596c84c99e3f12e13ad27321639fe07d55acf260efd25782bdbe5f60d62d120e89f9d725df1b20a067c2a8381dd0e793da6881e9e5bcc476997086d91843489da50423cdfc0042c89a69d559a515264f73c3c569243c0ad53aa445
// m_plaintext: Cassiano agora inverte esta mensagem e envia ela de volta cifrada
//       m_inv: adarfic atlov ed ale aivne e megasnem atse etrevni aroga onaissaC
//
//**********************************************************************************************************************

public class Main {
    private static BigInteger p_prime, q_prime, N_a, L_euler, e_a, d_a, s_value, e_teacherKey, N_teacherKey, x_key, sig_x, h_c, expected_h_c, sig_c, h_inv, sig_h_inv;
    private static String[] teacherKey = {"2E76A0094D4CEE0AC516CA162973C895", "1985008F25A025097712D26B5A322982B6EBAFA5826B6EDA3B91F78B7BD63981382581218D33A9983E4E14D4B26113AA2A83BBCCFDE24310AEE3362B6100D06CC1EA429018A0FF3614C077F59DE55AADF449AF01E42ED6545127DC1A97954B89729249C6060BA4BD3A59490839072929C0304B2D7CBBA368AEBC4878A6F0DA3FE58CECDA638A506C723BDCBAB8C355F83C0839BF1457A3B6B89307D672BBF530C93F022E693116FE4A5703A665C6010B5192F6D1FAB64B5795876B2164C86ABD7650AEDAF5B6AFCAC0438437BB3BDF5399D80F8D9963B5414EAFBFA1AA2DD0D24988ACECA8D50047E5A78082295A987369A67D3E54FFB7996CBE2C5EAD794391"};
    private static BigInteger[] publicKey = new BigInteger[2];
    private static BigInteger[] privateKey = new BigInteger[2];

    private static String[] xSigPkHex = new String[4];

    private static String cTeacher = "E13AB087A49BBEC699AC5DEB165533D342CC552FD707EA483DDAA57404A7F7A984761C461F78FABDE29B91EFF5265B4D248837D9912CE1BF44DDC2263239A4B1DF3275DE1D73332202DA2234DC0782CE10D76A5E41F17DDFF9CAA385A358C48C";
    private static String sig_cTeacher = "04D915CC3D899326CBD0FF0828CED625ED09F82DC28C9F86BCADED4F7975DA87ADBB7C3181DE237B13C7F050555099E4EEFC4AEBF497893498AFBBF6B41E094ED229501B0BBFADB7F58514815AB6C73C683EA1FD78AC95AC16F14A1A009B05BC46C8C05A435F8B297C16FD7695826A6D5B376E2DB14C02FEAA7BB6D8C45A019BA01C883C00C2A939465C163D450CB50E9212DF19589ABE62CF71C4491213E4486E2B489EDC655FF7A0F9E51F125B378C1B2908A08089872BA8B2A0A90A2912F5D29E8B70C5BA88D9C2C6DC255E25782F233F15DD519C70EED3FE24C1E512AD290369F9FA789942DBBF84385E568B5B80A03ABFB59A8BE2665A380C78838C6484";

    private static String s_valueFixed = "72862267910800375299092212796851321816";

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Parte 1

        // gera os dois primos p e q
        p_prime = generatePrime(1024);
        q_prime = generatePrime(1024);

        // calcula Na = p * q
        N_a = p_prime.multiply(q_prime);

        // calcula L = (p-1).(q-1)
        L_euler = calcEulerFunction(p_prime, q_prime);

        // encontra um e_a que seja primo relativo de L_euler
        findRelativePrime();

        // calcula o inverso d_a de e_a em Z_L
        d_a = e_a.modInverse(L_euler);

        // guarda os valores de pk_a e sk_a
        // pk_a = (e_a, N_a)
        publicKey[0] = e_a;
        publicKey[1] = N_a;
        // sk_a = (d_a, N_a)
        privateKey[0] = d_a;
        privateKey[1] = N_a;

        // valor aleatório s_value de 128 bits
        // s_value = generateRandomValue(128);
        // inicialmente gerei um valor aleatório e enviei para o professor, agora defino um s_value fixo
        s_value = new BigInteger(s_valueFixed);

        // calcula x = s^(e_teacherKey) mod N_(teacherKey)
        e_teacherKey = new BigInteger(teacherKey[0], 16);
        N_teacherKey = new BigInteger(teacherKey[1], 16);
        x_key = s_value.modPow(e_teacherKey, N_teacherKey);

        // calcula sig_x = x_key^(d_a) mod N_a
        sig_x = x_key.modPow(d_a, N_a);

        // enviar (x, sigx, pka) para o professor em hexadecimal
        xSigPkHex[0] = validateKey(x_key).toString(16);
        xSigPkHex[1] = validateKey(sig_x).toString(16);
        xSigPkHex[2] = validateKey(publicKey[0]).toString(16);
        xSigPkHex[3] = validateKey(publicKey[1]).toString(16);

        // exibe o que será enviado
        System.out.println("(x, sig_x, pk_a):");
        System.out.println(xSigPkHex[0]);
        System.out.println(xSigPkHex[1]);
        System.out.println(xSigPkHex[2]);
        System.out.println(xSigPkHex[3]);

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Parte 2
        byte[] cTeacherBytes, iv, ciphertext, keyBytes, plaintextBytes, newIV, encrypted_m_inv, c_inv;
        String m_plaintext, m_inv, c_inv_hex, sig_h_inv_hex;
        keyBytes = s_value.toByteArray();

        // calcula h_c = SHA-256(cTeacher)
        h_c = calcSHA256(cTeacher);

        // calcula o h_c esperado (sig_cTeacher^(e_p) mod N_p)
        sig_c = new BigInteger(sig_cTeacher, 16);
        expected_h_c = sig_c.modPow(e_teacherKey, N_teacherKey);

        if (!h_c.equals(expected_h_c)) {
            System.out.println("\nSignatures don't match! Exiting...\n");
            return;
        } else {
            System.out.println("\nSignatures checked!\n");
        }

        // transforma em array de bytes e separa IV do Ciphertext
        cTeacherBytes = hexToBytes(cTeacher);
        iv = Arrays.copyOfRange(cTeacherBytes, 0, 16);
        ciphertext = Arrays.copyOfRange(cTeacherBytes, 16, cTeacherBytes.length);

        // decifra a mensagem
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        plaintextBytes = cipher.doFinal(ciphertext);

        // converte a mensagem decifrada de bytes para string e inverte
        m_plaintext = new String(plaintextBytes, "UTF-8");
        m_inv = new StringBuilder(m_plaintext).reverse().toString();
        System.out.println("Decrypted messages:");
        System.out.println(m_plaintext);
        System.out.println(m_inv+"\n");

        // gera um IV aleatório
        newIV = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(newIV);

        // cifra a mensagem invertida
        SecretKeySpec newKey = new SecretKeySpec(keyBytes, "AES");
        Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, newKey, new IvParameterSpec(newIV));
        encrypted_m_inv = encryptCipher.doFinal(m_inv.getBytes("UTF-8"));

        // concatena IV e a mensagem cifrada
        c_inv = new byte[newIV.length + encrypted_m_inv.length];
        System.arraycopy(newIV, 0, c_inv, 0, newIV.length);
        System.arraycopy(encrypted_m_inv, 0, c_inv, newIV.length, encrypted_m_inv.length);

        // converte c_inv para hexadecimal
        c_inv_hex = bytesToHex(c_inv);

        // calcula h_inv = SHA-256(c_inv)
        h_inv = calcSHA256(c_inv_hex);

        // calcula sig_h_inv = h_inv^(d_a) mod N_a
        sig_h_inv = h_inv.modPow(d_a, N_a);

        // converte sig_h_inv para hexadecimal
        sig_h_inv_hex = sig_h_inv.toString(16);

        // enviar (c_inv, sig_h_inv) para o professor em hexadecimal
        System.out.println("(c_inv, sig_h_inv):");
        System.out.println(c_inv_hex);
        System.out.println(sig_h_inv_hex);
    }

    // gera um número primo de acordo com o número de bits
    private static BigInteger generatePrime(int bits) {
        SecureRandom random = new SecureRandom();
        return new BigInteger(bits, 100, random);
    }

    // calcula a função de Euler φ(n) = (p-1) * (q-1)
    private static BigInteger calcEulerFunction(BigInteger p, BigInteger q) {
        return p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    }

    // encontra um número que seja primo relativo de L_euler
    private static void findRelativePrime() {
        SecureRandom random = new SecureRandom();
        do {
            e_a = new BigInteger(128, random);
        } while (e_a.compareTo(BigInteger.ONE) <= 0 || e_a.compareTo(L_euler) >= 0 || !e_a.gcd(L_euler).equals(BigInteger.ONE));
    }

    // valida a chave e adiciona byte 0 no início se necessário
    private static BigInteger validateKey(BigInteger key) {
        String hex = key.toString(16);
        if (hex.matches("^[89ABCDEF].*")) {
            return new BigInteger("00" + hex, 16);
        }
        return key;
    }

    // gera um valor aleatório de acordo com o número de bits
    private static BigInteger generateRandomValue(int bits) {
        SecureRandom random = new SecureRandom();
        return new BigInteger(bits, random);
    }

    // converte uma string hexadecimal para um array de bytes
    private static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    // converte um array de bytes para uma string hexadecimal
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static BigInteger calcSHA256(String cHex) throws NoSuchAlgorithmException {
        // converte a mensagem cifrada hexadecimal para bytes
        byte[] cBytes = hexToBytes(cHex);

        // calcula o SHA-256
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(cBytes);

        // converte o hash SHA-256 para BigInteger
        return new BigInteger(1, hashBytes);
    }
}
