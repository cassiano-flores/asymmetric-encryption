import java.math.BigInteger;
import java.security.SecureRandom;

//******************************************************************************
//
// Classe responsável por gerar números primos de acordo com o número de bits
//
//******************************************************************************
public class PrimeGenerator {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("ERROR! \nUsage: java PrimeGenerator <number_of_bits>");
            return;
        }

        int bits = Integer.parseInt(args[0]);
        BigInteger prime = generatePrime(bits);
        System.out.println("PrimeGenerator: " + prime);
    }

    public static BigInteger generatePrime(int bits) {
        SecureRandom random = new SecureRandom();
        return new BigInteger(bits, 100, random);
    }
}
