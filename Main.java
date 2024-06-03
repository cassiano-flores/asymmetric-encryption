import java.math.BigInteger;
import java.security.SecureRandom;

public class Main {
    private static BigInteger p_prime, q_prime, N_a, L_euler, e_a, d_a;
    private static String publicKey, privateKey;

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

        // Valida as chaves e adiciona byte 0 no início se necessário
        e_a = validateKey(e_a);
        d_a = validateKey(d_a);

        // Converte a chave pública e privada para hexadecimal e concatena com N_a
        publicKey = e_a.toString(16) + N_a.toString(16);  // pk_a = (e_a, N_a)
        privateKey = d_a.toString(16) + N_a.toString(16); // sk_a = (d_a, N_a)

        // Exibe as chaves pública e privada em hexadecimal
        System.out.println("chave publica (e_a, N_a) em hexadecimal: " + publicKey);
        System.out.println("chave privada (d_a, N_a) em hexadecimal: " + privateKey);
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
            e_a = new BigInteger(L_euler.bitLength(), random);
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
}
