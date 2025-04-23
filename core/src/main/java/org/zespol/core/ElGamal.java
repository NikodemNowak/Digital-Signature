package org.zespol.core;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class ElGamal {
    private static final int DEFAULT_CERTAINTY = 100; // Pewność testu pierwszości Millera-Rabina
    private static final SecureRandom random = new SecureRandom();
    private BigInteger p;
    private BigInteger g;
    private BigInteger publicKey;
    private BigInteger privateKey;

    /**
     * Konstruktor przyjmujący gotowe parametry p i g.
     * Klucze należy wygenerować osobno metodą generateKeys().
     */
    public ElGamal(BigInteger p, BigInteger g) {
        if (p == null || g == null) {
            throw new IllegalArgumentException("Parametry p i g nie mogą być null.");
        }
        // Podstawowa walidacja (można dodać więcej sprawdzeń)
        if (!p.isProbablePrime(DEFAULT_CERTAINTY)) {
            System.err.println("Ostrzeżenie: Podane 'p' może nie być liczbą pierwszą.");
        }
        // Tutaj można by dodać sprawdzenie czy g jest generatorem, ale jest to złożone.
        this.p = p;
        this.g = g;

    }

    /**
     * Generuje parametry p i g.
     * UWAGA: Generowanie bezpiecznych parametrów ElGamal jest złożone.
     * Ta metoda jest uproszczona i może nie generować parametrów
     * o wystarczającej sile kryptograficznej do rzeczywistych zastosowań.
     * Zazwyczaj p powinno być tzw. "bezpieczną liczbą pierwszą".
     *
     * @param bitLength Długość bitowa liczby pierwszej p.
     * @return Nowa instancja ElGamal z wygenerowanymi p i g. Klucze trzeba wygenerować osobno.
     */
    public static ElGamal generateParameters(int bitLength) {
        BigInteger p;

        // Generuj p - dużą liczbę pierwszą
        do {
            p = BigInteger.probablePrime(bitLength, random);
        } while (p.bitLength() != bitLength);

        BigInteger g = BigInteger.TWO;

        System.out.println("Wygenerowano parametry:");
        System.out.println("p (hex): " + p.toString(16));
        System.out.println("g (hex): " + g.toString(16));

        return new ElGamal(p, g);
    }

    public void generateKeys() {
        if (p == null || g == null) {
            throw new IllegalStateException("Parametry p i g nie zostały zainicjowane.");
        }

        // Klucz prywatny x: losowa liczba z zakresu 1 < x < p-1
        BigInteger pMinusOne = p.subtract(BigInteger.ONE);

        do {
            // Generuj x o długości bitowej zbliżonej do p, ale mniejszej niż p-1
            privateKey = new BigInteger(p.bitLength() - 1, random);
        } while (privateKey.compareTo(BigInteger.ONE) <= 0 || privateKey.compareTo(pMinusOne) >= 0);

        // Klucz publiczny y = g^x mod p
        publicKey = g.modPow(privateKey, p);

        // W praktyce klucze trzeba bezpiecznie przechowywać/eksportować
        System.out.println("\nWygenerowano klucze:");
        System.out.println("Klucz prywatny x (hex): " + privateKey.toString(16));
        System.out.println("Klucz publiczny y (hex): " + publicKey.toString(16));
    }

    /**
     * Haszuje wiadomość przy użyciu SHA-256.
     *
     * @param message Wiadomość jako tablica bajtów.
     * @return Skrót wiadomości jako BigInteger.
     * @throws NoSuchAlgorithmException Jeśli algorytm SHA-256 nie jest dostępny.
     */
    private BigInteger hashMessage(byte[] message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(message);
        // Konwertuj bajty hasha na dodatnią liczbę BigInteger
        return new BigInteger(1, hashBytes);
    }

    /**
     * Podpisuje wiadomość przy użyciu wygenerowanego klucza prywatnego.
     *
     * @param message Wiadomość do podpisania jako tablica bajtów.
     * @return Tablica [r, s] reprezentująca podpis.
     * @throws IllegalStateException    Jeśli klucze nie zostały wygenerowane.
     * @throws NoSuchAlgorithmException Jeśli algorytm SHA-256 nie jest dostępny.
     */
    public BigInteger[] sign(byte[] message) throws NoSuchAlgorithmException {
        if (privateKey == null || p == null || g == null) {
            throw new IllegalStateException("Klucze lub parametry nie zostały zainicjowane.");
        }

        BigInteger pMinusOne = p.subtract(BigInteger.ONE);
        BigInteger k, r, s;

        // 1. Oblicz skrót wiadomości H(m)
        BigInteger mHash = hashMessage(message);

        // 2. Wygeneruj losowe k takie, że 1 < k < p-1 oraz NWD(k, p-1) = 1
        do {
            k = new BigInteger(p.bitLength() - 1, random);
        } while (k.compareTo(BigInteger.ONE) <= 0 || k.compareTo(pMinusOne) >= 0 || !k.gcd(pMinusOne).equals(BigInteger.ONE));

        // 3. Oblicz r = g^k mod p
        r = g.modPow(k, p);

        // 4. Oblicz s = (H(m) - x*r) * k^(-1) mod (p-1)

        // 4.1 Oblicz k^(-1) mod (p-1)
        BigInteger kInv = k.modInverse(pMinusOne);

        // 4.2 Oblicz xr = x * r
        BigInteger xr = privateKey.multiply(r);

        // 4.3 Oblicz H(m) - xr
        BigInteger mMinusXr = mHash.subtract(xr);

        // 4.4 Oblicz s = mMinusXr * k^(-1) mod (p-1)
        // Używamy .mod() aby wynik był zawsze w zakresie [0, p-1]
        s = mMinusXr.multiply(kInv).mod(pMinusOne);

        // Wynik podpisu to tablica [r, s]
        return new BigInteger[]{r, s};
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getG() {
        return g;
    }
}
