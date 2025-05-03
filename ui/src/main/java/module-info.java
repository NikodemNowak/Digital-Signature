module org.zespol.ui {
    requires javafx.controls;
    requires javafx.fxml;

    requires org.controlsfx.controls;
    requires com.dlsc.formsfx;

    requires org.zespol.core;

    opens org.zespol.ui to javafx.fxml;
    exports org.zespol.ui;
}