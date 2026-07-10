from PySide6.QtWidgets import (QWidget, QVBoxLayout, QLabel, QFrame, 
                             QGridLayout)
from PySide6.QtCore import Qt

class AboutPage(QWidget):
    """
    AboutPage displays academic, developer, and research information for the project.
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(25)
        
        # 1. Header
        header_layout = QVBoxLayout()
        title_label = QLabel("ABOUT THE PROJECT")
        title_label.setStyleSheet("font-size: 26px; font-weight: bold; color: #10b981;")
        subtitle_label = QLabel("Academic and research paper reference details.")
        subtitle_label.setStyleSheet("color: #94a3b8; font-size: 14px;")
        header_layout.addWidget(title_label)
        header_layout.addWidget(subtitle_label)
        layout.addLayout(header_layout)
        
        # 2. Main Card containing info
        about_card = QFrame()
        about_card.setObjectName("Card")
        about_layout = QVBoxLayout(about_card)
        about_layout.setSpacing(20)
        
        # Project Title inside Card
        lbl_p_name = QLabel("Android Credential Leakage Detection System V2")
        lbl_p_name.setStyleSheet("font-size: 20px; font-weight: bold; color: #10b981;")
        about_layout.addWidget(lbl_p_name)
        
        # Description
        lbl_desc = QLabel(
            "An intelligent mobile application vulnerability assessment framework. "
            "It decompiles Android APK files, extracts Smali bytecode and values assets, and runs "
            "a rule-based heuristics scanner mapped directly to the OWASP Mobile Top 10 standard. "
            "It correlates static findings with active dynamic logs (logcat) and unencrypted network "
            "traces (PCAP) to output a confidence-weighted security risk score between 0 and 100."
        )
        lbl_desc.setWordWrap(True)
        lbl_desc.setStyleSheet("color: #cbd5e1; font-size: 14px; line-height: 1.5;")
        about_layout.addWidget(lbl_desc)
        
        # Divider
        divider = QFrame()
        divider.setFrameShape(QFrame.HLine)
        divider.setStyleSheet("background-color: #334155;")
        about_layout.addWidget(divider)
        
        # Metadata grid
        meta_grid = QGridLayout()
        meta_grid.setSpacing(15)
        
        # Info labels styling
        label_style = "font-weight: bold; color: #10b981; font-size: 13px;"
        val_style = "color: #f8fafc; font-size: 13px;"
        
        # Add items to grid
        meta_grid.addWidget(QLabel("Current Version:"), 0, 0)
        meta_grid.addWidget(QLabel("2.0.0 (Upgrade Build)"), 0, 1)
        meta_grid.itemAtPosition(0, 0).widget().setStyleSheet(label_style)
        meta_grid.itemAtPosition(0, 1).widget().setStyleSheet(val_style)
        
        meta_grid.addWidget(QLabel("Developer / Author:"), 1, 0)
        meta_grid.addWidget(QLabel("Veera bhadhra"), 1, 1)
        meta_grid.itemAtPosition(1, 0).widget().setStyleSheet(label_style)
        meta_grid.itemAtPosition(1, 1).widget().setStyleSheet(val_style)
        
        meta_grid.addWidget(QLabel("Supervisor / Panel:"), 2, 0)
        meta_grid.addWidget(QLabel("Final Year Project Review Committee"), 2, 1)
        meta_grid.itemAtPosition(2, 0).widget().setStyleSheet(label_style)
        meta_grid.itemAtPosition(2, 1).widget().setStyleSheet(val_style)
        
        meta_grid.addWidget(QLabel("Affiliated University:"), 3, 0)
        meta_grid.addWidget(QLabel("Parul University"), 3, 1)
        meta_grid.itemAtPosition(3, 0).widget().setStyleSheet(label_style)
        meta_grid.itemAtPosition(3, 1).widget().setStyleSheet(val_style)
        
        meta_grid.addWidget(QLabel("Research Paper Title:"), 4, 0)
        lbl_paper = QLabel("<b>Automated Static and Dynamic Risk-Weighted Android Credential Leakage Detection Framework</b>")
        lbl_paper.setWordWrap(True)
        meta_grid.addWidget(lbl_paper, 4, 1)
        meta_grid.itemAtPosition(4, 0).widget().setStyleSheet(label_style)
        meta_grid.itemAtPosition(4, 1).widget().setStyleSheet(val_style)
        
        meta_grid.addWidget(QLabel("GitHub Repository:"), 5, 0)
        meta_grid.addWidget(QLabel("https://github.com/kvr585/android-credential-leakage-detector"), 5, 1)
        meta_grid.itemAtPosition(5, 0).widget().setStyleSheet(label_style)
        meta_grid.itemAtPosition(5, 1).widget().setStyleSheet(val_style)
        
        meta_grid.addWidget(QLabel("Release License:"), 6, 0)
        meta_grid.addWidget(QLabel("MIT Open-Source Academic License"), 6, 1)
        meta_grid.itemAtPosition(6, 0).widget().setStyleSheet(label_style)
        meta_grid.itemAtPosition(6, 1).widget().setStyleSheet(val_style)
        
        about_layout.addLayout(meta_grid)
        about_layout.addStretch()
        
        layout.addWidget(about_card)
        layout.addStretch()
