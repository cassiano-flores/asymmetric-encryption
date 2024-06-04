import java.math.BigInteger;
import java.security.SecureRandom;

public class Main {
    private static BigInteger p_prime, q_prime, N_a, L_euler, e_a, d_a, s_value, e_teacherKey, N_teacherKey, x_key, sig_x;
    private static String[] teacherKey = {"2E76A0094D4CEE0AC516CA162973C895", "1985008F25A025097712D26B5A322982B6EBAFA5826B6EDA3B91F78B7BD63981382581218D33A9983E4E14D4B26113AA2A83BBCCFDE24310AEE3362B6100D06CC1EA429018A0FF3614C077F59DE55AADF449AF01E42ED6545127DC1A97954B89729249C6060BA4BD3A59490839072929C0304B2D7CBBA368AEBC4878A6F0DA3FE58CECDA638A506C723BDCBAB8C355F83C0839BF1457A3B6B89307D672BBF530C93F022E693116FE4A5703A665C6010B5192F6D1FAB64B5795876B2164C86ABD7650AEDAF5B6AFCAC0438437BB3BDF5399D80F8D9963B5414EAFBFA1AA2DD0D24988ACECA8D50047E5A78082295A987369A67D3E54FFB7996CBE2C5EAD794391"};
    private static BigInteger[] publicKey = new BigInteger[2];
    private static BigInteger[] privateKey = new BigInteger[2];

    private static String[] xSigPkHex = new String[4];

    public static void main(String[] args) {
        // Gera os dois primos p e q
        p_prime = generatePrime(1024);
        q_prime = generatePrime(1024);

        // Calcula Na = p * q
        N_a = p_prime.multiply(q_prime);

        // Calcula L = (p-1).(q-1)
        L_euler = calculateEulerFunction(p_prime, q_prime);

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
        System.out.println("(x, sigx, pka):");
        System.out.println(xSigPkHex[0]);
        System.out.println(xSigPkHex[1]);
        System.out.println(xSigPkHex[2]);
        System.out.println(xSigPkHex[3]);
    }

    // Gera um número primo de acordo com o número de bits
    private static BigInteger generatePrime(int bits) {
        SecureRandom random = new SecureRandom();
        return new BigInteger(bits, 100, random);
    }

    // Calcula a função de Euler φ(n) = (p-1) * (q-1)
    private static BigInteger calculateEulerFunction(BigInteger p, BigInteger q) {
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
}
