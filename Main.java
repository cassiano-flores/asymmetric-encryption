import java.math.BigInteger;
import java.security.SecureRandom;

public class Main {
    private static BigInteger p, q, module, eulerFunction;

    public static void main(String[] args) {
        // Gera os dois primos p e q
        p = generatePrime(1024);
        q = generatePrime(1024);
        // Calcula Na = p * q
        module = p.multiply(q);
        // Calcula função de Euler
        eulerFunction = calculateEulerFunction(p, q);

        //....

        System.out.printf(" p: %s\n q: %s\n module: %s\n eulerFunction: %s\n", p, q, module, eulerFunction);
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
}
