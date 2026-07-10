import sys
import os

# Set High DPI scaling environment attributes before QApplication instantiation
os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
os.environ["QT_SCALE_FACTOR"] = "1"

from PySide6.QtWidgets import QApplication
from ui.mainwindow import MainWindow
from __version__ import VERSION

def main():
    """
    Main entry point for launching the Android Credential Leakage Detector Desktop GUI.
    """
    app = QApplication(sys.argv)
    
    # Establish application metadata
    app.setApplicationName("Android Credential Leakage Detection System V2")
    app.setApplicationVersion(VERSION)
    app.setOrganizationName("Parul University Capstone")
    
    # Instantiate and render main window
    window = MainWindow()
    window.show()
    
    # Start the event loop
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
