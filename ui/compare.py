import os
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QLineEdit, QFileDialog, QFrame, 
                             QProgressBar, QTextEdit, QMessageBox, QTableWidget, 
                             QTableWidgetItem, QHeaderView, QTabWidget)
from PySide6.QtCore import Qt, Signal

class ComparePage(QWidget):
    """
    ComparePage handles selecting two APKs to compute delta differences in 
    vulnerabilities, risk scores, and mapping categories.
    """
    comparison_started = Signal(dict)
    comparison_cancelled = Signal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        
    def init_ui(self):
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(30, 30, 30, 30)
        self.main_layout.setSpacing(20)
        
        # 1. Header
        title_layout = QVBoxLayout()
        title_label = QLabel("COMPARE APKS")
        title_label.setStyleSheet("font-size: 26px; font-weight: bold; color: #10b981;")
        subtitle_label = QLabel("Compare security posture, risk delta score, and vulnerabilities between two APK builds.")
        subtitle_label.setStyleSheet("color: #94a3b8; font-size: 14px;")
        title_layout.addWidget(title_label)
        title_layout.addWidget(subtitle_label)
        self.main_layout.addLayout(title_layout)
        
        # 2. Config Card
        self.config_card = QFrame()
        self.config_card.setObjectName("Card")
        config_layout = QVBoxLayout(self.config_card)
        config_layout.setSpacing(15)
        
        # Old APK
        lbl_old = QLabel("Older APK File Path *")
        lbl_old.setStyleSheet("font-weight: bold;")
        config_layout.addWidget(lbl_old)
        
        old_lay = QHBoxLayout()
        self.txt_old_apk = QLineEdit()
        self.txt_old_apk.setPlaceholderText("Select base/vulnerable APK...")
        btn_browse_old = QPushButton("Browse")
        btn_browse_old.setObjectName("SecondaryBtn")
        btn_browse_old.clicked.connect(self.browse_old_apk)
        old_lay.addWidget(self.txt_old_apk)
        old_lay.addWidget(btn_browse_old)
        config_layout.addLayout(old_lay)
        
        # New APK
        lbl_new = QLabel("Newer / Patched APK File Path *")
        lbl_new.setStyleSheet("font-weight: bold;")
        config_layout.addWidget(lbl_new)
        
        new_lay = QHBoxLayout()
        self.txt_new_apk = QLineEdit()
        self.txt_new_apk.setPlaceholderText("Select upgraded/remediated APK...")
        btn_browse_new = QPushButton("Browse")
        btn_browse_new.setObjectName("SecondaryBtn")
        btn_browse_new.clicked.connect(self.browse_new_apk)
        new_lay.addWidget(self.txt_new_apk)
        new_lay.addWidget(btn_browse_new)
        config_layout.addLayout(new_lay)
        
        # Dynamic Folder
        lbl_dyn = QLabel("Runtime Logs Folder (Optional)")
        lbl_dyn.setStyleSheet("font-weight: bold;")
        config_layout.addWidget(lbl_dyn)
        
        dyn_lay = QHBoxLayout()
        self.txt_dynamic_path = QLineEdit()
        self.txt_dynamic_path.setPlaceholderText("Directory containing runtime traces...")
        btn_browse_dyn = QPushButton("Browse")
        btn_browse_dyn.setObjectName("SecondaryBtn")
        btn_browse_dyn.clicked.connect(self.browse_dynamic)
        dyn_lay.addWidget(self.txt_dynamic_path)
        dyn_lay.addWidget(btn_browse_dyn)
        config_layout.addLayout(dyn_lay)
        
        # Output Folder
        lbl_out = QLabel("Output Folder (Defaults to reports/)")
        lbl_out.setStyleSheet("font-weight: bold;")
        config_layout.addWidget(lbl_out)
        
        out_lay = QHBoxLayout()
        self.txt_output_path = QLineEdit(os.path.abspath("reports"))
        btn_browse_out = QPushButton("Browse")
        btn_browse_out.setObjectName("SecondaryBtn")
        btn_browse_out.clicked.connect(self.browse_output)
        out_lay.addWidget(self.txt_output_path)
        out_lay.addWidget(btn_browse_out)
        config_layout.addLayout(out_lay)
        
        # Compare Button
        btn_compare = QPushButton("START APK POSTURE DIFF")
        btn_compare.setObjectName("PrimaryBtn")
        btn_compare.clicked.connect(self.start_comparison_clicked)
        config_layout.addWidget(btn_compare)
        
        self.main_layout.addWidget(self.config_card)
        
        # 3. Progress Card (Hidden by default)
        self.progress_card = QFrame()
        self.progress_card.setObjectName("Card")
        self.progress_card.setVisible(False)
        progress_layout = QVBoxLayout(self.progress_card)
        
        progress_title = QLabel("RUNNING POSTURE ANALYSIS DELTA")
        progress_title.setObjectName("CardTitle")
        progress_layout.addWidget(progress_title)
        
        self.lbl_progress_step = QLabel("Step: Initializing...")
        self.lbl_progress_step.setStyleSheet("font-weight: bold; color: #10b981;")
        progress_layout.addWidget(self.lbl_progress_step)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(18)
        progress_layout.addWidget(self.progress_bar)
        
        self.console = QTextEdit()
        self.console.setObjectName("Console")
        self.console.setReadOnly(True)
        progress_layout.addWidget(self.console, 1)
        
        btn_cancel = QPushButton("Terminate Comparison")
        btn_cancel.setObjectName("SecondaryBtn")
        btn_cancel.clicked.connect(self.cancel_comparison)
        progress_layout.addWidget(btn_cancel)
        
        self.main_layout.addWidget(self.progress_card, 1)
        
        # 4. Results Display (Hidden by default)
        self.results_card = QFrame()
        self.results_card.setObjectName("Card")
        self.results_card.setVisible(False)
        results_layout = QVBoxLayout(self.results_card)
        results_layout.setSpacing(15)
        
        res_title = QLabel("COMPARISON RESULTS DELTA")
        res_title.setObjectName("CardTitle")
        results_layout.addWidget(res_title)
        
        # Stats summary layout
        stats_layout = QHBoxLayout()
        
        self.lbl_old_score = self.create_summary_stat("OLD APK SCORE")
        self.lbl_new_score = self.create_summary_stat("NEW APK SCORE")
        self.lbl_score_delta = self.create_summary_stat("RISK DELTA")
        self.lbl_improvement = self.create_summary_stat("IMPROVEMENT")
        
        stats_layout.addWidget(self.lbl_old_score)
        stats_layout.addWidget(self.lbl_new_score)
        stats_layout.addWidget(self.lbl_score_delta)
        stats_layout.addWidget(self.lbl_improvement)
        results_layout.addLayout(stats_layout)
        
        # Summary description
        self.lbl_summary_text = QLabel("Comparison Summary details...")
        self.lbl_summary_text.setStyleSheet("color: #cbd5e1; font-size: 14px; padding: 10px; background-color: #0f172a; border-radius: 6px;")
        self.lbl_summary_text.setWordWrap(True)
        results_layout.addWidget(self.lbl_summary_text)
        
        # Tabs for Removed/Added Vulnerabilities
        self.tabs = QTabWidget()
        
        self.table_removed = QTableWidget(0, 4)
        self.table_removed.setHorizontalHeaderLabels(["Category", "Severity", "Location", "Evidence"])
        self.table_removed.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tabs.addTab(self.table_removed, "Removed Vulnerabilities (Patched)")
        
        self.table_added = QTableWidget(0, 4)
        self.table_added.setHorizontalHeaderLabels(["Category", "Severity", "Location", "Evidence"])
        self.table_added.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tabs.addTab(self.table_added, "New/Added Vulnerabilities")
        
        results_layout.addWidget(self.tabs, 1)
        
        btn_back = QPushButton("Configure New Comparison")
        btn_back.setObjectName("SecondaryBtn")
        btn_back.clicked.connect(self.show_config)
        results_layout.addWidget(btn_back)
        
        self.main_layout.addWidget(self.results_card, 1)
        
    def create_summary_stat(self, label: str) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        card.setStyleSheet("background-color: #0f172a;")
        lay = QVBoxLayout(card)
        lay.setAlignment(Qt.AlignCenter)
        
        lbl = QLabel(label)
        lbl.setStyleSheet("font-size: 10px; color: #94a3b8; font-weight: bold;")
        val = QLabel("0.0")
        val.setStyleSheet("font-size: 20px; color: #10b981; font-weight: 800;")
        
        lay.addWidget(lbl, 0, Qt.AlignCenter)
        lay.addWidget(val, 0, Qt.AlignCenter)
        card.setProperty("val_widget", val)
        return card
        
    def browse_old_apk(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Old APK", "", "Android Package (*.apk)")
        if file_path:
            self.txt_old_apk.setText(file_path)
            
    def browse_new_apk(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select New APK", "", "Android Package (*.apk)")
        if file_path:
            self.txt_new_apk.setText(file_path)
            
    def browse_dynamic(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Runtime Directory")
        if dir_path:
            self.txt_dynamic_path.setText(dir_path)
            
    def browse_output(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if dir_path:
            self.txt_output_path.setText(dir_path)
            
    def start_comparison_clicked(self):
        old_apk = self.txt_old_apk.text().strip()
        new_apk = self.txt_new_apk.text().strip()
        output_dir = self.txt_output_path.text().strip()
        dynamic_dir = self.txt_dynamic_path.text().strip()
        
        if not old_apk or not new_apk:
            QMessageBox.critical(self, "Validation Error", "Both base and target APK paths are required.")
            return
            
        if not os.path.exists(old_apk) or not os.path.exists(new_apk):
            QMessageBox.critical(self, "Validation Error", "One of the selected APK file paths does not exist.")
            return
            
        if not output_dir:
            output_dir = "reports"
            
        # Toggle to progress view
        self.config_card.setVisible(False)
        self.results_card.setVisible(False)
        self.progress_card.setVisible(True)
        
        self.progress_bar.setValue(0)
        self.console.clear()
        self.lbl_progress_step.setText("Step: Initializing posture comparison...")
        
        self.comparison_started.emit({
            "old_apk": old_apk,
            "new_apk": new_apk,
            "dynamic_dir": dynamic_dir,
            "output_dir": output_dir,
            "verbose": True
        })
        
    def cancel_comparison(self):
        self.comparison_cancelled.emit()
        self.show_config()
        
    def show_config(self):
        self.progress_card.setVisible(False)
        self.results_card.setVisible(False)
        self.config_card.setVisible(True)
        
    def append_log(self, text: str):
        self.console.append(text)
        
    def update_progress(self, val: int):
        self.progress_bar.setValue(val)
        
    def update_step(self, step_text: str):
        self.lbl_progress_step.setText(f"Step: {step_text}")
        
    def set_finished(self, success: bool):
        if success:
            self.lbl_progress_step.setText("Comparison completed successfully!")
        else:
            self.lbl_progress_step.setText("Comparison failed. See logs.")
            
    def display_results(self, data: dict):
        self.progress_card.setVisible(False)
        self.results_card.setVisible(True)
        
        # Populate metrics
        self.lbl_old_score.property("val_widget").setText(f"{data.get('old_apk_risk_score', 0.0):.2f}")
        self.lbl_new_score.property("val_widget").setText(f"{data.get('new_apk_risk_score', 0.0):.2f}")
        self.lbl_score_delta.property("val_widget").setText(f"{data.get('risk_difference', 0.0):.2f}")
        self.lbl_improvement.property("val_widget").setText(f"{data.get('risk_improvement_percentage', 0.0):.1f}%")
        
        # Set text color dynamically for improvement (Green if positive, Red if negative)
        score_diff = data.get('risk_difference', 0.0)
        col = "#10b981" if score_diff >= 0 else "#ef4444"
        self.lbl_score_delta.property("val_widget").setStyleSheet(f"font-size: 20px; font-weight: 800; color: {col};")
        
        self.lbl_summary_text.setText(data.get("comparison_summary", "No details available."))
        
        # Populate Tables
        self.populate_vulnerability_table(self.table_removed, data.get("removed_vulnerabilities", []))
        self.populate_vulnerability_table(self.table_added, data.get("new_vulnerabilities", []))
        
    def populate_vulnerability_table(self, table: QTableWidget, list_items: list):
        table.setRowCount(0)
        for idx, item in enumerate(list_items):
            table.insertRow(idx)
            table.setItem(idx, 0, QTableWidgetItem(item.get("category", "N/A")))
            table.setItem(idx, 1, QTableWidgetItem(item.get("severity", "LOW")))
            table.setItem(idx, 2, QTableWidgetItem(item.get("location", "N/A")))
            table.setItem(idx, 3, QTableWidgetItem(item.get("evidence", "N/A")))
