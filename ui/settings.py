import os
import json
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QComboBox, QCheckBox, QFrame, 
                             QFileDialog, QMessageBox, QLineEdit)
from PySide6.QtCore import Signal

SETTINGS_FILE = "settings.json"

class SettingsPage(QWidget):
    """
    SettingsPage controls configuring the user interface, paths, and themes.
    Saves configurations persistently to settings.json.
    """
    settings_changed = Signal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(25)
        
        # 1. Header
        header_layout = QVBoxLayout()
        title_label = QLabel("SYSTEM SETTINGS")
        title_label.setStyleSheet("font-size: 26px; font-weight: bold; color: #10b981;")
        subtitle_label = QLabel("Customize theme options, default output paths, and log levels.")
        subtitle_label.setStyleSheet("color: #94a3b8; font-size: 14px;")
        header_layout.addWidget(title_label)
        header_layout.addWidget(subtitle_label)
        layout.addLayout(header_layout)
        
        # 2. Settings Card
        config_card = QFrame()
        config_card.setObjectName("Card")
        config_layout = QVBoxLayout(config_card)
        config_layout.setSpacing(20)
        
        # Theme Select
        theme_lay = QHBoxLayout()
        lbl_theme = QLabel("Application Theme")
        lbl_theme.setStyleSheet("font-weight: bold; font-size: 14px;")
        self.cmb_theme = QComboBox()
        self.cmb_theme.addItems(["Dark", "Light", "Cyber Green"])
        theme_lay.addWidget(lbl_theme)
        theme_lay.addWidget(self.cmb_theme)
        config_layout.addLayout(theme_lay)
        
        # Default Output Path
        path_lay = QVBoxLayout()
        lbl_path = QLabel("Default Output Reports Folder")
        lbl_path.setStyleSheet("font-weight: bold; font-size: 14px;")
        path_lay.addWidget(lbl_path)
        
        browse_lay = QHBoxLayout()
        self.txt_output_dir = QLineEdit()
        self.txt_output_dir.setPlaceholderText("Select folder...")
        btn_browse = QPushButton("Browse")
        btn_browse.setObjectName("SecondaryBtn")
        btn_browse.clicked.connect(self.browse_folder)
        browse_lay.addWidget(self.txt_output_dir)
        browse_lay.addWidget(btn_browse)
        path_lay.addLayout(browse_lay)
        config_layout.addLayout(path_lay)
        
        # Verbose Logging Checkbox
        self.chk_verbose = QCheckBox("Enable Verbose Logging by Default")
        self.chk_verbose.setStyleSheet("font-weight: bold; font-size: 14px;")
        config_layout.addWidget(self.chk_verbose)
        
        # Actions
        btn_save = QPushButton("SAVE SETTINGS")
        btn_save.setObjectName("PrimaryBtn")
        btn_save.clicked.connect(self.save_settings)
        config_layout.addWidget(btn_save)
        
        layout.addWidget(config_card)
        layout.addStretch()
        
        # Load initial values
        self.load_settings()
        
    def browse_folder(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if dir_path:
            self.txt_output_dir.setText(dir_path)
            
    def load_settings(self) -> dict:
        """Loads and returns configurations from settings.json."""
        default_config = {
            "theme": "Dark",
            "default_output_dir": os.path.abspath("reports"),
            "verbose_logging": False
        }
        
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                    config = json.load(f)
                    # Merge keys to ensure compatibility
                    for k, v in default_config.items():
                        if k not in config:
                            config[k] = v
                    self.txt_output_dir.setText(config["default_output_dir"])
                    self.cmb_theme.setCurrentText(config["theme"])
                    self.chk_verbose.setChecked(config["verbose_logging"])
                    return config
            except Exception:
                pass
                
        self.txt_output_dir.setText(default_config["default_output_dir"])
        self.cmb_theme.setCurrentText(default_config["theme"])
        self.chk_verbose.setChecked(default_config["verbose_logging"])
        return default_config
        
    def save_settings(self):
        """Saves current widget values to settings.json and emits signal."""
        config = {
            "theme": self.cmb_theme.currentText(),
            "default_output_dir": self.txt_output_dir.text().strip(),
            "verbose_logging": self.chk_verbose.isChecked()
        }
        
        try:
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)
            self.settings_changed.emit(config)
            QMessageBox.information(self, "Success", "Settings saved successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save settings: {e}")
