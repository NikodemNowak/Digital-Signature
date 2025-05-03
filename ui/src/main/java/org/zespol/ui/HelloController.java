package org.zespol.ui;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.zespol.core.ElGamal; // Zaimportuj swoją klasę ElGamal

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Properties; // Do łatwego zapisu/odczytu kluczy

public class HelloController {

    // --- Elementy FXML ---
    @FXML private TextField bitLengthField;
    @FXML private TextField pField;
    @FXML private TextField gField;
    @FXML private TextField xField;
    @FXML private TextField yField;
    @FXML private TextField rField;
    @FXML private TextField sField;
    @FXML private TextArea messageArea;
    @FXML private Label selectedFileLabel;
    @FXML private TextField verificationResultField;
    @FXML private Label statusLabel;

    // --- Instancja ElGamal ---
    private final ElGamal elGamal = new ElGamal();

    // --- Zmienne pomocnicze ---
    private File selectedFile = null; // Przechowuje wybrany plik do podpisu/weryfikacji
    private final FileChooser fileChooser = new FileChooser(); // Do wyboru plików

    // --- Metody Inicjalizacyjne (opcjonalne, można tu np. ustawić filtry FileChooser) ---
    @FXML
    private void initialize() {
        // Konfiguracja FileChooser (np. filtry dla plików kluczy/podpisów)
        fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("Pliki kluczy ElGamal (*.key, *.pub)", "*.key", "*.pub"),
                new FileChooser.ExtensionFilter("Pliki podpisów ElGamal (*.sig)", "*.sig"),
                new FileChooser.ExtensionFilter("Wszystkie pliki (*.*)", "*.*")
        );
        updateStatus("Gotowy.", false);
    }


    @FXML
    void handleGenerateKeys(ActionEvent event) {
        try {
            int bitLength = Integer.parseInt(bitLengthField.getText().trim());
            if (bitLength < 16) { // Minimalna rozsądna długość dla testów
                showAlert(Alert.AlertType.WARNING, "Generowanie Kluczy", "Nieprawidłowa długość bitowa.", "Podaj większą długość bitową (np. 512).");
                return;
            }

            updateStatus("Generowanie parametrów p i g...", false);
            List<BigInteger> pg = elGamal.generateParameters(bitLength);
            BigInteger p = pg.get(0);
            BigInteger g = pg.get(1);

            updateStatus("Generowanie klucza prywatnego x...", false);
            BigInteger x = elGamal.generatePrivateKey(pg);

            updateStatus("Generowanie klucza publicznego y...", false);
            List<BigInteger> publicKey = elGamal.generatePublicKey(pg, x);
            BigInteger y = publicKey.get(2); // y jest na indeksie 2

            // Wyświetl wyniki w polach
            pField.setText(p.toString(16));
            gField.setText(g.toString(16));
            xField.setText(x.toString(16));
            yField.setText(y.toString(16));

            // Wyczyść stare dane podpisu i weryfikacji
            rField.clear();
            sField.clear();
            verificationResultField.clear();
            updateStatus("Klucze i parametry wygenerowane pomyślnie.", false);

        } catch (NumberFormatException e) {
            showAlert(Alert.AlertType.ERROR, "Błąd Wejścia", "Nieprawidłowy format długości bitowej.", "Wpisz liczbę całkowitą.");
            updateStatus("Błąd: Nieprawidłowa długość bitowa.", true);
        } catch (Exception e) { // Ogólny handler dla innych błędów ElGamal
            showAlert(Alert.AlertType.ERROR, "Błąd Generowania", "Wystąpił błąd podczas generowania kluczy.", e.getMessage());
            updateStatus("Błąd generowania kluczy.", true);
            e.printStackTrace(); // Wypisz stack trace do konsoli dla debugowania
        }
    }

    @FXML
    void handleSavePrivateKey(ActionEvent event) {
        String p = pField.getText();
        String g = gField.getText();
        String x = xField.getText();

        if (p.isEmpty() || g.isEmpty() || x.isEmpty()) {
            showAlert(Alert.AlertType.WARNING, "Zapis Klucza Prywatnego", "Brak danych.", "Wygeneruj lub wczytaj klucze najpierw.");
            return;
        }

        fileChooser.setTitle("Zapisz Klucz Prywatny");
        fileChooser.getExtensionFilters().set(0, new FileChooser.ExtensionFilter("Plik klucza prywatnego (*.key)", "*.key")); // Ustaw domyślny filtr
        File file = fileChooser.showSaveDialog(getStage());

        if (file != null) {
            Properties props = new Properties();
            props.setProperty("p", p);
            props.setProperty("g", g);
            props.setProperty("x", x);
            try (FileOutputStream fos = new FileOutputStream(file)) {
                props.store(fos, "ElGamal Private Key");
                updateStatus("Klucz prywatny zapisany do: " + file.getName(), false);
            } catch (IOException e) {
                showAlert(Alert.AlertType.ERROR, "Błąd Zapisu", "Nie można zapisać klucza prywatnego.", e.getMessage());
                updateStatus("Błąd zapisu klucza prywatnego.", true);
            }
        }
    }

    @FXML
    void handleSavePublicKey(ActionEvent event) {
        String p = pField.getText();
        String g = gField.getText();
        String y = yField.getText(); // Używamy Y dla klucza publicznego

        if (p.isEmpty() || g.isEmpty() || y.isEmpty()) {
            showAlert(Alert.AlertType.WARNING, "Zapis Klucza Publicznego", "Brak danych.", "Wygeneruj lub wczytaj klucze najpierw.");
            return;
        }

        fileChooser.setTitle("Zapisz Klucz Publiczny");
        fileChooser.getExtensionFilters().set(0, new FileChooser.ExtensionFilter("Plik klucza publicznego (*.pub)", "*.pub"));
        File file = fileChooser.showSaveDialog(getStage());

        if (file != null) {
            Properties props = new Properties();
            props.setProperty("p", p);
            props.setProperty("g", g);
            props.setProperty("y", y); // Zapisujemy Y
            try (FileOutputStream fos = new FileOutputStream(file)) {
                props.store(fos, "ElGamal Public Key");
                updateStatus("Klucz publiczny zapisany do: " + file.getName(), false);
            } catch (IOException e) {
                showAlert(Alert.AlertType.ERROR, "Błąd Zapisu", "Nie można zapisać klucza publicznego.", e.getMessage());
                updateStatus("Błąd zapisu klucza publicznego.", true);
            }
        }
    }

    @FXML
    void handleLoadPrivateKey(ActionEvent event) {
        fileChooser.setTitle("Wczytaj Klucz Prywatny");
        fileChooser.getExtensionFilters().set(0, new FileChooser.ExtensionFilter("Plik klucza prywatnego (*.key)", "*.key"));
        File file = fileChooser.showOpenDialog(getStage());

        if (file != null) {
            Properties props = new Properties();
            try (FileInputStream fis = new FileInputStream(file)) {
                props.load(fis);
                String pStr = props.getProperty("p");
                String gStr = props.getProperty("g");
                String xStr = props.getProperty("x");

                if (pStr == null || gStr == null || xStr == null) {
                    throw new IOException("Niekompletny plik klucza prywatnego.");
                }

                // Podstawowa walidacja formatu hex
                BigInteger p = new BigInteger(pStr, 16);
                BigInteger g = new BigInteger(gStr, 16);
                BigInteger x = new BigInteger(xStr, 16);

                pField.setText(pStr);
                gField.setText(gStr);
                xField.setText(xStr);

                // Oblicz i ustaw Y na podstawie wczytanych p, g, x
                List<BigInteger> pg = List.of(p, g);
                List<BigInteger> publicKey = elGamal.generatePublicKey(pg, x);
                yField.setText(publicKey.get(2).toString(16));

                // Wyczyść stare dane podpisu i weryfikacji
                rField.clear();
                sField.clear();
                verificationResultField.clear();
                updateStatus("Klucz prywatny wczytany z: " + file.getName(), false);

            } catch (IOException | NumberFormatException | NullPointerException e) {
                showAlert(Alert.AlertType.ERROR, "Błąd Odczytu", "Nie można wczytać lub sparsować klucza prywatnego.", e.getMessage());
                updateStatus("Błąd wczytywania klucza prywatnego.", true);
            } catch (Exception e) { // Inne błędy, np. z generatePublicKey
                showAlert(Alert.AlertType.ERROR, "Błąd Przetwarzania", "Wystąpił błąd podczas przetwarzania klucza prywatnego.", e.getMessage());
                updateStatus("Błąd przetwarzania klucza prywatnego.", true);
            }
        }
    }

    @FXML
    void handleLoadPublicKey(ActionEvent event) {
        fileChooser.setTitle("Wczytaj Klucz Publiczny");
        fileChooser.getExtensionFilters().set(0, new FileChooser.ExtensionFilter("Plik klucza publicznego (*.pub)", "*.pub"));
        File file = fileChooser.showOpenDialog(getStage());

        if (file != null) {
            Properties props = new Properties();
            try (FileInputStream fis = new FileInputStream(file)) {
                props.load(fis);
                String pStr = props.getProperty("p");
                String gStr = props.getProperty("g");
                String yStr = props.getProperty("y"); // Odczytujemy Y

                if (pStr == null || gStr == null || yStr == null) {
                    throw new IOException("Niekompletny plik klucza publicznego.");
                }

                // Podstawowa walidacja formatu hex
                new BigInteger(pStr, 16);
                new BigInteger(gStr, 16);
                new BigInteger(yStr, 16);

                pField.setText(pStr);
                gField.setText(gStr);
                yField.setText(yStr);
                xField.clear(); // Wyczyść pole klucza prywatnego, bo go nie znamy

                // Wyczyść stare dane podpisu i weryfikacji
                rField.clear();
                sField.clear();
                verificationResultField.clear();
                updateStatus("Klucz publiczny wczytany z: " + file.getName(), false);

            } catch (IOException | NumberFormatException | NullPointerException e) {
                showAlert(Alert.AlertType.ERROR, "Błąd Odczytu", "Nie można wczytać lub sparsować klucza publicznego.", e.getMessage());
                updateStatus("Błąd wczytywania klucza publicznego.", true);
            }
        }
    }


    @FXML
    void handleSaveSignature(ActionEvent event) {
        String r = rField.getText();
        String s = sField.getText();
        if (r.isEmpty() || s.isEmpty()) {
            showAlert(Alert.AlertType.WARNING, "Zapis Podpisu", "Brak danych.", "Wygeneruj podpis najpierw.");
            return;
        }

        fileChooser.setTitle("Zapisz Podpis");
        fileChooser.getExtensionFilters().set(0, new FileChooser.ExtensionFilter("Plik podpisu (*.sig)", "*.sig"));
        File file = fileChooser.showSaveDialog(getStage());

        if (file != null) {
            Properties props = new Properties();
            props.setProperty("r", r);
            props.setProperty("s", s);
            try (FileOutputStream fos = new FileOutputStream(file)) {
                props.store(fos, "ElGamal Signature");
                updateStatus("Podpis zapisany do: " + file.getName(), false);
            } catch (IOException e) {
                showAlert(Alert.AlertType.ERROR, "Błąd Zapisu", "Nie można zapisać podpisu.", e.getMessage());
                updateStatus("Błąd zapisu podpisu.", true);
            }
        }
    }

    @FXML
    void handleLoadSignature(ActionEvent event) {
        fileChooser.setTitle("Wczytaj Podpis");
        fileChooser.getExtensionFilters().set(0, new FileChooser.ExtensionFilter("Plik podpisu (*.sig)", "*.sig"));
        File file = fileChooser.showOpenDialog(getStage());

        if (file != null) {
            Properties props = new Properties();
            try (FileInputStream fis = new FileInputStream(file)) {
                props.load(fis);
                String rStr = props.getProperty("r");
                String sStr = props.getProperty("s");

                if (rStr == null || sStr == null) {
                    throw new IOException("Niekompletny plik podpisu.");
                }

                // Podstawowa walidacja formatu hex
                new BigInteger(rStr, 16);
                new BigInteger(sStr, 16);

                rField.setText(rStr);
                sField.setText(sStr);
                verificationResultField.clear(); // Wyczyść stary wynik weryfikacji
                updateStatus("Podpis wczytany z: " + file.getName(), false);

            } catch (IOException | NumberFormatException | NullPointerException e) {
                showAlert(Alert.AlertType.ERROR, "Błąd Odczytu", "Nie można wczytać lub sparsować podpisu.", e.getMessage());
                updateStatus("Błąd wczytywania podpisu.", true);
            }
        }
    }

    @FXML
    void handleChooseFile(ActionEvent event) {
        fileChooser.setTitle("Wybierz plik do podpisania/weryfikacji");
        // Użyj ostatnio ustawionego lub domyślnego filtra (np. "Wszystkie pliki")
        fileChooser.getExtensionFilters().set(0, new FileChooser.ExtensionFilter("Wszystkie pliki (*.*)", "*.*"));
        File file = fileChooser.showOpenDialog(getStage());

        if (file != null) {
            selectedFile = file;
            selectedFileLabel.setText(selectedFile.getName());
            messageArea.clear(); // Wyczyść pole tekstowe, gdy plik jest wybrany
            messageArea.setDisable(true); // Opcjonalnie zablokuj pole tekstowe
            updateStatus("Wybrano plik: " + selectedFile.getName(), false);
        }     }

    @FXML
    void handleSignMessage(ActionEvent event) {
        try {
            // 1. Pobierz klucz prywatny i parametry
            BigInteger p = getBigIntegerFromField(pField, "Parametr p");
            BigInteger g = getBigIntegerFromField(gField, "Parametr g");
            BigInteger x = getBigIntegerFromField(xField, "Klucz prywatny x");

            if (p == null || g == null || x == null) return; // Błąd został już pokazany w getBigIntegerFromField

            List<BigInteger> pg = List.of(p, g);

            // 2. Pobierz dane do podpisania (plik lub tekst)
            byte[] dataToSign = getDataToProcess();
            if (dataToSign == null) return; // Komunikat o błędzie pokazany w getDataToProcess

            // 3. Wykonaj podpisywanie
            updateStatus("Podpisywanie...", false);
            List<BigInteger> signature = elGamal.sign(dataToSign, x, pg);

            // 4. Wyświetl podpis
            rField.setText(signature.get(0).toString(16));
            sField.setText(signature.get(1).toString(16));
            verificationResultField.clear(); // Wyczyść stary wynik weryfikacji
            updateStatus("Podpisywanie zakończone pomyślnie.", false);

        } catch (NoSuchAlgorithmException e) {
            showAlert(Alert.AlertType.ERROR, "Błąd Podpisywania", "Nie znaleziono algorytmu SHA-256.", e.getMessage());
            updateStatus("Błąd: Brak SHA-256.", true);
        } catch (Exception e) {
            showAlert(Alert.AlertType.ERROR, "Błąd Podpisywania", "Wystąpił nieoczekiwany błąd podczas podpisywania.", e.getMessage());
            updateStatus("Błąd podpisywania.", true);
            e.printStackTrace();
        }
    }

    @FXML
    void handleVerifySignature(ActionEvent event) {
        try {
            // 1. Pobierz klucz publiczny, parametry i podpis
            BigInteger p = getBigIntegerFromField(pField, "Parametr p");
            BigInteger g = getBigIntegerFromField(gField, "Parametr g");
            BigInteger y = getBigIntegerFromField(yField, "Klucz publiczny y");
            BigInteger r = getBigIntegerFromField(rField, "Podpis r");
            BigInteger s = getBigIntegerFromField(sField, "Podpis s");

            if (p == null || g == null || y == null || r == null || s == null) return;

            List<BigInteger> publicKey = List.of(p, g, y);
            List<BigInteger> signature = List.of(r, s);

            // 2. Pobierz dane do weryfikacji (plik lub tekst)
            byte[] dataToVerify = getDataToProcess();
            if (dataToVerify == null) return;

            // 3. Wykonaj weryfikację
            updateStatus("Weryfikowanie...", false);
            boolean isValid = elGamal.verify(dataToVerify, signature, publicKey);

            // 4. Wyświetl wynik
            if (isValid) {
                verificationResultField.setText("POPRAWNY");
                // Opcjonalnie zmień styl pola na zielony
                verificationResultField.setStyle("-fx-text-fill: green; -fx-font-weight: bold;");
                updateStatus("Weryfikacja zakończona: Podpis jest poprawny.", false);
            } else {
                verificationResultField.setText("NIEPOPRAWNY");
                // Opcjonalnie zmień styl pola na czerwony
                verificationResultField.setStyle("-fx-text-fill: red; -fx-font-weight: bold;");
                updateStatus("Weryfikacja zakończona: Podpis jest niepoprawny.", false); // To niekoniecznie błąd, więc isError = false
            }

        } catch (NoSuchAlgorithmException e) {
            showAlert(Alert.AlertType.ERROR, "Błąd Weryfikacji", "Nie znaleziono algorytmu SHA-256.", e.getMessage());
            updateStatus("Błąd: Brak SHA-256.", true);
        } catch (IllegalArgumentException e) { // Specjalnie dla błędów zakresu r, s z metody verify
            showAlert(Alert.AlertType.WARNING, "Błąd Weryfikacji", "Podpis poza wymaganym zakresem.", e.getMessage());
            updateStatus("Błąd weryfikacji: podpis poza zakresem.", true);
            verificationResultField.setText("BŁĄD ZAKRESU");
            verificationResultField.setStyle("-fx-text-fill: orange;");
        } catch (Exception e) {
            showAlert(Alert.AlertType.ERROR, "Błąd Weryfikacji", "Wystąpił nieoczekiwany błąd podczas weryfikacji.", e.getMessage());
            updateStatus("Błąd weryfikacji.", true);
            e.printStackTrace();
        }
    }

    // --- Metody Pomocnicze ---

    /** Pobiera dane do przetworzenia (z pliku lub z pola tekstowego). */
    private byte[] getDataToProcess() {
        byte[] data = null;
        if (selectedFile != null && selectedFile.exists()) {
            try {
                data = Files.readAllBytes(selectedFile.toPath());
                if (data.length == 0) {
                    showAlert(Alert.AlertType.WARNING, "Pusty Plik", "Wybrany plik jest pusty.", selectedFile.getName());
                    updateStatus("Ostrzeżenie: Wybrany plik jest pusty.", false);
                    return null; // Zwróć null, jeśli plik jest pusty
                }
                updateStatus("Przetwarzanie danych z pliku: " + selectedFile.getName(), false);
            } catch (IOException e) {
                showAlert(Alert.AlertType.ERROR, "Błąd Odczytu Pliku", "Nie można odczytać wybranego pliku.", e.getMessage());
                updateStatus("Błąd odczytu pliku.", true);
                return null;
            }
        } else {
            if (!messageArea.isDisabled() && !messageArea.getText().isEmpty()) {
                data = messageArea.getText().getBytes(StandardCharsets.UTF_8);
                updateStatus("Przetwarzanie danych z pola tekstowego.", false);
            } else {
                showAlert(Alert.AlertType.WARNING, "Brak Danych", "Nie wybrano pliku ani nie wpisano wiadomości.", "Wpisz wiadomość lub wybierz plik.");
                updateStatus("Brak danych do przetworzenia.", true);
                return null;
            }
        }
        return data;
    }


    /** Pobiera BigInteger z pola tekstowego, waliduje i pokazuje błąd. */
    private BigInteger getBigIntegerFromField(TextField field, String fieldName) {
        String text = field.getText().trim();
        if (text.isEmpty()) {
            showAlert(Alert.AlertType.WARNING, "Brak Danych", "Pole jest puste: " + fieldName, "Wprowadź lub wczytaj wymaganą wartość.");
            updateStatus("Brak danych w polu: " + fieldName, true);
            return null;
        }
        try {
            return new BigInteger(text, 16); // Radix 16 dla hex
        } catch (NumberFormatException e) {
            showAlert(Alert.AlertType.ERROR, "Błąd Formatu", "Nieprawidłowy format szesnastkowy w polu: " + fieldName, text);
            updateStatus("Błąd formatu w polu: " + fieldName, true);
            return null;
        }
    }

    /** Wyświetla standardowy Alert JavaFX. */
    private void showAlert(Alert.AlertType type, String title, String header, String content) {
        Alert alert = new Alert(type);
        alert.setTitle(title);
        alert.setHeaderText(header);
        alert.setContentText(content);
        // Ustaw właściciela, aby alert był modalny względem głównego okna
        alert.initOwner(getStage());
        alert.showAndWait();
    }

    /** Aktualizuje etykietę statusu na dole okna. */
    private void updateStatus(String message, boolean isError) {
        statusLabel.setText(message);
        if (isError) {
            statusLabel.setStyle("-fx-text-fill: red;");
        } else {
            statusLabel.setStyle("-fx-text-fill: yellow;"); // Domyślny kolor z FXML
        }
        System.out.println("Status: " + message); // Logowanie do konsoli
    }

    /** Zwraca obiekt Stage głównego okna (potrzebne dla FileChooser i Alert). */
    private Stage getStage() {
        // Próbuje uzyskać Stage z dowolnego dostępnego elementu FXML
        if (statusLabel != null && statusLabel.getScene() != null && statusLabel.getScene().getWindow() != null) {
            return (Stage) statusLabel.getScene().getWindow();
        }
        return null;
    }
}