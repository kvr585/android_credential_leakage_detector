import os
import json
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QFrame, QGridLayout, QTableWidget, 
                             QTableWidgetItem, QHeaderView)
from PySide6.QtCore import Qt, Signal, QUrl
from PySide6.QtGui import QDesktopServices

class DashboardPage(QWidget):
    """
    Dashboard Page representing the home landing view of the GUI.
    Renders overview metrics and quick links.
    """
    navigate_to_page = Signal(int)  # Signal to request main window page index changes
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(25)
        
        # 1. Header
        header_layout = QVBoxLayout()
        title_label = QLabel("SYSTEM DASHBOARD")
        title_label.setStyleSheet("font-size: 26px; font-weight: bold; color: #10b981;")
        subtitle_label = QLabel("Overview of scan metrics, rules metadata, and quick launch triggers.")
        subtitle_label.setStyleSheet("color: #94a3b8; font-size: 14px;")
        header_layout.addWidget(title_label)
        header_layout.addWidget(subtitle_label)
        layout.addLayout(header_layout)
        
        # 2. Metric Grid Layout
        self.grid_layout = QGridLayout()
        self.grid_layout.setSpacing(20)
        
        # Placeholders for statistics cards
        self.card_total_scans = self.create_metric_card("TOTAL SCANS", "0")
        self.card_last_risk = self.create_metric_card("LAST RISK RATING", "N/A")
        self.card_last_score = self.create_metric_card("LAST RISK SCORE", "0.0")
        self.card_rules_count = self.create_metric_card("STATIC RULES ACTIVE", "0")
        
        self.grid_layout.addWidget(self.card_total_scans, 0, 0)
        self.grid_layout.addWidget(self.card_last_risk, 0, 1)
        self.grid_layout.addWidget(self.card_last_score, 0, 2)
        self.grid_layout.addWidget(self.card_rules_count, 0, 3)
        layout.addLayout(self.grid_layout)
        
        # 3. Middle Section: Quick Actions & Database Metadata
        middle_layout = QHBoxLayout()
        middle_layout.setSpacing(30)
        
        # Quick Actions Card
        actions_card = QFrame()
        actions_card.setObjectName("Card")
        actions_layout = QVBoxLayout(actions_card)
        actions_layout.setSpacing(15)
        
        actions_title = QLabel("QUICK SEC-OPERATIONS")
        actions_title.setObjectName("CardTitle")
        actions_layout.addWidget(actions_title)
        
        btn_analyze = QPushButton("Launch single APK scan")
        btn_analyze.setObjectName("PrimaryBtn")
        btn_analyze.clicked.connect(lambda: self.navigate_to_page.emit(1)) # Analyze APK page index
        
        btn_compare = QPushButton("Launch APK Diff/Comparison")
        btn_compare.setObjectName("SecondaryBtn")
        btn_compare.clicked.connect(lambda: self.navigate_to_page.emit(2)) # Compare APK page index
        
        btn_folder = QPushButton("Browse Reports Output directory")
        btn_folder.setObjectName("SecondaryBtn")
        btn_folder.clicked.connect(self.open_reports_folder)
        
        actions_layout.addWidget(btn_analyze)
        actions_layout.addWidget(btn_compare)
        actions_layout.addWidget(btn_folder)
        actions_layout.addStretch()
        
        # Database Metadata Card
        db_card = QFrame()
        db_card.setObjectName("Card")
        db_layout = QVBoxLayout(db_card)
        db_layout.setSpacing(15)
        
        db_title = QLabel("INTELLIGENCE BASE STATS")
        db_title.setObjectName("CardTitle")
        db_layout.addWidget(db_title)
        
        self.lbl_owasp = QLabel("OWASP Mappings: M1 - M10 Loaded")
        self.lbl_owasp.setStyleSheet("color: #cbd5e1; font-size: 13px;")
        self.lbl_cwe = QLabel("CWE Vulnerabilities Catalog: 12 definitions")
        self.lbl_cwe.setStyleSheet("color: #cbd5e1; font-size: 13px;")
        self.lbl_dynamic = QLabel("Dynamic Analysis Rules: 11 active check signatures")
        self.lbl_dynamic.setStyleSheet("color: #cbd5e1; font-size: 13px;")
        
        db_layout.addWidget(self.lbl_owasp)
        db_layout.addWidget(self.lbl_cwe)
        db_layout.addWidget(self.lbl_dynamic)
        db_layout.addStretch()
        
        middle_layout.addWidget(actions_card, 1)
        middle_layout.addWidget(db_card, 1)
        layout.addLayout(middle_layout)
        
        # 4. Recent Scan History Table Card
        history_card = QFrame()
        history_card.setObjectName("Card")
        history_layout = QVBoxLayout(history_card)
        history_layout.setSpacing(15)
        
        history_title = QLabel("RECENT SCAN HISTORY (LATEST 5 OPERATIONS)")
        history_title.setObjectName("CardTitle")
        history_layout.addWidget(history_title)
        
        self.table_history = QTableWidget(0, 5)
        self.table_history.setHorizontalHeaderLabels(["APK Name", "Scan Date", "Risk Rating", "Risk Score", "Status"])
        self.table_history.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_history.setAlternatingRowColors(True)
        self.table_history.verticalHeader().setVisible(False)
        self.table_history.setStyleSheet("QTableWidget { border: none; background-color: transparent; }")
        
        history_layout.addWidget(self.table_history)
        layout.addWidget(history_card, 2)
        
        # Load initially
        self.refresh_data()
        
    def create_metric_card(self, title: str, val: str) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        card_layout = QVBoxLayout(card)
        card_layout.setAlignment(Qt.AlignCenter)
        card_layout.setSpacing(5)
        
        lbl_title = QLabel(title)
        lbl_title.setStyleSheet("font-size: 11px; font-weight: bold; color: #94a3b8;")
        
        lbl_val = QLabel(val)
        lbl_val.setStyleSheet("font-size: 28px; font-weight: 800; color: #10b981;")
        
        card_layout.addWidget(lbl_title, 0, Qt.AlignCenter)
        card_layout.addWidget(lbl_val, 0, Qt.AlignCenter)
        
        # Store value widget reference for updates
        card.setProperty("val_widget", lbl_val)
        return card
        
    def refresh_data(self):
        """Loads rules.json and history.json to update metric counts and table."""
        # 1. Rules Count
        rules_path = "rules.json"
        rules_cnt = 0
        if os.path.exists(rules_path):
            try:
                with open(rules_path, "r", encoding="utf-8") as f:
                    rules_cnt = len(json.load(f))
            except Exception:
                rules_cnt = 5
        else:
            rules_cnt = 5
        self.card_rules_count.property("val_widget").setText(str(rules_cnt))
        
        # 2. History File
        history_path = os.path.join("reports", "history.json")
        scans = []
        if os.path.exists(history_path):
            try:
                with open(history_path, "r", encoding="utf-8") as f:
                    scans = json.load(f)
            except Exception:
                pass
                
        total_scans = len(scans)
        self.card_total_scans.property("val_widget").setText(str(total_scans))
        
        if total_scans > 0:
            last_scan = scans[-1]
            last_risk = last_scan.get("risk", "INFO")
            last_score = last_scan.get("score", 0.0)
            
            self.card_last_risk.property("val_widget").setText(str(last_risk))
            self.card_last_score.property("val_widget").setText(f"{last_score:.2f}")
            
            # Color code risk label
            lbl_risk = self.card_last_risk.property("val_widget")
            color_map = {
                "CRITICAL": "#ef4444",
                "HIGH": "#f97316",
                "MEDIUM": "#f59e0b",
                "LOW": "#3b82f6",
                "INFO": "#10b981"
            }
            lbl_risk.setStyleSheet(f"font-size: 28px; font-weight: 800; color: {color_map.get(last_risk.upper(), '#10b981')};")
        else:
            self.card_last_risk.property("val_widget").setText("N/A")
            self.card_last_score.property("val_widget").setText("0.0")
            
        # 3. Populate Recent History Table
        self.table_history.setRowCount(0)
        recent_scans = scans[-5:][::-1]  # Show last 5 in reverse chronological order
        for idx, scan in enumerate(recent_scans):
            self.table_history.insertRow(idx)
            self.table_history.setItem(idx, 0, QTableWidgetItem(scan.get("apk_name", "N/A")))
            self.table_history.setItem(idx, 1, QTableWidgetItem(scan.get("date", "N/A")))
            self.table_history.setItem(idx, 2, QTableWidgetItem(scan.get("risk", "INFO")))
            self.table_history.setItem(idx, 3, QTableWidgetItem(f"{scan.get('score', 0.0):.2f}"))
            self.table_history.setItem(idx, 4, QTableWidgetItem(scan.get("status", "DONE")))
            
    def open_reports_folder(self):
        reports_dir = os.path.abspath("reports")
        os.makedirs(reports_dir, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(reports_dir))
