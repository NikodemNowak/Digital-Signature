package org.zespol.core;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class ElGamal {
    private BigInteger p;
    private BigInteger g;

    private BigInteger publicKey;
    private BigInteger privateKey;

    private static final int DEFAULT_CERTAINTY = 100; // Pewność testu pierwszości Millera-Rabina
    private static final SecureRandom random = new SecureRandom();

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


    public BigInteger getP() {
        return p;
    }
    public BigInteger getG() {
        return g;
    }
}
