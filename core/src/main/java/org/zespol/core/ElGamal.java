package org.zespol.core;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class ElGamal {
    private static final int DEFAULT_CERTAINTY = 100; // Pewność testu pierwszości Millera-Rabina
    private static final SecureRandom random = new SecureRandom();


    /**
     * Generuje parametry p i g.
     * UWAGA: Generowanie bezpiecznych parametrów ElGamal jest złożone.
     * Ta metoda jest uproszczona i może nie generować parametrów
     * o wystarczającej sile kryptograficznej do rzeczywistych zastosowań.
     *
     * @param bitLength Długość bitowa liczby pierwszej p.
     * @return pg - lista [p, g]
     */
    public List<BigInteger> generateParameters(int bitLength) {
        BigInteger p;

        // Generuj p - dużą liczbę pierwszą
        do {
            // Generuje liczbę o CO NAJMNIEJ takiej długości a my chcemy konkretnie tą długość, więć do while
            p = BigInteger.probablePrime(bitLength, random);
        } while (p.bitLength() != bitLength);

        // Generuj g - generator grupy multiplikatywnej Z_p^*;
        // Oznacza to, że g^1 mod p, ..., g^(p-1) mod p da zbiór wszystkich liczb od 1 do p-1

        // Znalezienie generatora wymaga znajomości faktoryzacji p-1.
        // Prostsze (ale nie zawsze poprawne/bezpieczne) podejście to wybranie losowej liczby
        // i sprawdzenie kilku warunków lub użycie stałej wartości jak 2, jeśli warunki są spełnione.

        // Tutaj dla uproszczenia wybierzemy g=2, zakładając, że będzie działać.
        // W realnym systemie to wymagałoby porządnego algorytmu znajdowania generatora.

        BigInteger g = BigInteger.TWO;

        System.out.println("Wygenerowano parametry:");
        System.out.println("p (hex): " + p.toString(16));
        System.out.println("g (hex): " + g.toString(16));

        List<BigInteger> pg = new ArrayList<>();
        pg.add(p);
        pg.add(g);

        return pg;
    }


    /**
     * Generuje klucz prywatny x.
     * @param pg - lista [p, g]
     * @return x - liczba pierwsza x
     */
    public BigInteger generatePrivateKey(List<BigInteger> pg) {
        BigInteger p = pg.get(0);
        BigInteger g = pg.get(1);

        if (p == null || g == null) {
            throw new IllegalStateException("Parametry p i g nie zostały zainicjowane.");
        }

        BigInteger x;

        // Klucz prywatny x: losowa liczba z zakresu 1 <= x <= p-2
        BigInteger pMinusTwo = p.subtract(BigInteger.TWO); // zwraca p-2, BigInt nie ma zwykłych operacji arytmetycznych

        do {
            // Generuj x o długości bitowej zbliżonej do p, ale mniejszej niż p-1
            x = new BigInteger(p.bitLength() - 1, random);
        } while (x.compareTo(BigInteger.ONE) < 0 || x.compareTo(pMinusTwo) > 0);


        System.out.println("Klucz prywatny x (hex): " + x.toString(16));

        return x;
    }

    /**
     * Generuje klucz publiczny jako parametry [p, g, y].
     * @param pg - lista [p, g]
     * @param privateKey - liczba pierwsza x
     * @return publicKey - Lista [p, g, y]
     */
    public List<BigInteger> generatePublicKey(List<BigInteger> pg, BigInteger privateKey) {

        BigInteger p = pg.get(0);
        BigInteger g = pg.get(1);
        BigInteger x = privateKey;

        if (p == null || g == null) {
            throw new IllegalStateException("Parametry p i g nie zostały zainicjowane.");
        }

        BigInteger y;

        // y klucza publicznego y = g^x mod p
        y = g.modPow(x, p);

        List<BigInteger> publicKey = new ArrayList<>();
        publicKey.add(p);
        publicKey.add(g);
        publicKey.add(y);

        System.out.println("\nWygenerowano klucz:");

        System.out.println("Klucz publiczny (p, g, y) (hex): ");
        for (BigInteger el : publicKey) {
            System.out.print(el.toString(16) + " ");
        }

        return publicKey;
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
     * @param privateKey Klucz prywatny jako BigInteger.
     * @param pg Parametry p i g jako Lista [p, g].
     * @return Tablica [r, s] reprezentująca podpis.
     * @throws IllegalStateException    Jeśli klucze lub parametry nie zostały zainicjowane.
     * @throws NoSuchAlgorithmException Jeśli algorytm SHA-256 nie jest dostępny.
     */
    public List<BigInteger> sign(byte[] message, BigInteger privateKey, List<BigInteger> pg) throws NoSuchAlgorithmException {

        BigInteger x = privateKey;
        BigInteger p = pg.getFirst();
        BigInteger g = pg.get(1);


        if (x == null || p == null || g == null) {
            throw new IllegalStateException("Klucze lub parametry nie zostały zainicjowane.");
        }

        BigInteger pMinusOne = p.subtract(BigInteger.ONE);
        BigInteger pMinusTwo = pMinusOne.subtract(BigInteger.ONE); // p-2
        BigInteger k, r, s;

        // 1. Oblicz skrót wiadomości H(m)
        BigInteger mHash = hashMessage(message);

        // Pętla do generowania k, r, s - powtarzamy, jeśli s wyjdzie 0 (zgodnie ze standardem)
        do {
            // 2. Wygeneruj losowe k takie, że 1 <= k <= p-2 oraz NWD(k, p-1) = 1
            do {
                k = new BigInteger(p.bitLength() - 1, random);
                // Pętla działa dopóki k jest poza zakresem [1, p-2] LUB gcd(k, p-1) != 1
            } while (k.compareTo(BigInteger.ONE) < 0 || k.compareTo(pMinusTwo) > 0 || !k.gcd(pMinusOne).equals(BigInteger.ONE));

            // 3. Oblicz r = g^k mod p
            r = g.modPow(k, p);

            // 4. Oblicz s = (H(m) - x*r) * k^(-1) mod (p-1)

            // 4.1 Oblicz k^(-1) mod (p-1) - zadziała, bo gcd(k, p-1)=1
            BigInteger kInv = k.modInverse(pMinusOne);

            // 4.2 Oblicz xr = x * r
            BigInteger xr = x.multiply(r);

            // 4.3 Oblicz H(m) - xr
            BigInteger mMinusXr = mHash.subtract(xr);

            // 4.4 Oblicz s = (H(m) - xr) * k^(-1) mod (p-1)
            s = mMinusXr.multiply(kInv).mod(pMinusOne);

            // 5. Jeśli s = 0, standard ElGamal wymaga wygenerowania nowego k i powtórzenia kroków.
        } while (s.equals(BigInteger.ZERO));


        // Wynik podpisu lista r i s
        List<BigInteger> signature = new ArrayList<>();
        signature.add(r);
        signature.add(s);
        return signature;
    }


    /**
     * Weryfikuje podpis dla danej wiadomości przy użyciu klucza publicznego.
     * Używa formy weryfikacji g^H(m) == y^r * r^s (mod p), aby uniknąć problemów z s niemającym odwrotności mod (p-1).
     *
     * @param message Wiadomość jako tablica bajtów.
     * @param signature Podpis jako lista [r, s].
     * @param publicKey Klucz publiczny jako lista [p, g, y].
     * @return true jeśli podpis jest poprawny, false w przeciwnym razie.
     * @throws NoSuchAlgorithmException Jeśli algorytm SHA-256 nie jest dostępny.
     * @throws IllegalArgumentException Jeśli podpis ma niepoprawny format lub wartości r,s są poza zakresem.
     */
    public boolean verify(byte[] message, List<BigInteger> signature, List<BigInteger> publicKey) throws NoSuchAlgorithmException {

        BigInteger p = publicKey.get(0);
        BigInteger g = publicKey.get(1);
        BigInteger y = publicKey.get(2);

        BigInteger r = signature.get(0);
        BigInteger s = signature.get(1);

        if (y == null || p == null || g == null) {
            throw new IllegalStateException("Któryś z elementów klucza publicznego p, g, y jest null");
        }
        if (signature == null || signature.size() != 2 || r == null || s == null) {
            throw new IllegalArgumentException("Nieprawidłowy format podpisu.");
        }

        // 1. Sprawdź warunki: 0 < r < p oraz 0 < s < p-1
        BigInteger pMinusOne = p.subtract(BigInteger.ONE);
        if (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(p) >= 0 ||
                s.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(pMinusOne) >= 0) {
            System.err.println("Weryfikacja nie powiodła się: r lub s poza wymaganym zakresem.");
            return false;
        }

        // 2. Oblicz skrót wiadomości H(m)
        BigInteger mHash = hashMessage(message);

        // 3. Weryfikacja: Sprawdź czy g^H(m) ≡ y^r * r^s (mod p)

        // Oblicz lewą stronę: g^H(m) mod p
        BigInteger leftSide = g.modPow(mHash, p);

        // Oblicz prawą stronę: (y^r * r^s) mod p
        BigInteger yr = y.modPow(r, p);
        BigInteger rs = r.modPow(s, p);
        BigInteger rightSide = yr.multiply(rs).mod(p);

        // Sprawdź, czy strony są równe
        boolean isValid = leftSide.equals(rightSide);
        System.out.println("Wynik weryfikacji: g^H(m)=" + leftSide.toString(16) + ", y^r*r^s=" + rightSide.toString(16) + " -> " + (isValid ? "POPRAWNY" : "NIEPOPRAWNY"));
        return isValid;
    }
}
