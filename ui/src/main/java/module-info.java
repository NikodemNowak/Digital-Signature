module org.zespol.ui {
    requires javafx.controls;
    requires javafx.fxml;

    requires org.controlsfx.controls;
    requires com.dlsc.formsfx;

    opens org.zespol.ui to javafx.fxml;
    exports org.zespol.ui;
}