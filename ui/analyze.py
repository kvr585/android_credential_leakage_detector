import os
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QLineEdit, QFileDialog, QRadioButton, 
                             QButtonGroup, QCheckBox, QFrame, QProgressBar, 
                             QTextEdit, QMessageBox)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QDragEnterEvent, QDropEvent

class AnalyzePage(QWidget):
    """
    AnalyzePage designs the view where a user selects files, formats,
    runs the scan, and views live analysis progress.
    """
    analysis_started = Signal(dict)  # Emitted when the user starts an analysis
    analysis_cancelled = Signal()    # Emitted if the user cancels
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.init_ui()
        
    def init_ui(self):
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(30, 30, 30, 30)
        self.main_layout.setSpacing(20)
        
        # 1. Title
        title_layout = QVBoxLayout()
        title_label = QLabel("ANALYZE APK")
        title_label.setStyleSheet("font-size: 26px; font-weight: bold; color: #10b981;")
        subtitle_label = QLabel("Decompile, inspect code assets, parse dynamic logs, and check for leakage vulnerabilities.")
        subtitle_label.setStyleSheet("color: #94a3b8; font-size: 14px;")
        title_layout.addWidget(title_label)
        title_layout.addWidget(subtitle_label)
        self.main_layout.addLayout(title_layout)
        
        # 2. Main Config Card
        self.config_card = QFrame()
        self.config_card.setObjectName("Card")
        config_layout = QVBoxLayout(self.config_card)
        config_layout.setSpacing(15)
        
        # APK Path
        lbl_apk = QLabel("Target Android APK File Path * (Drag & Drop Supported)")
        lbl_apk.setStyleSheet("font-weight: bold;")
        config_layout.addWidget(lbl_apk)
        
        apk_file_layout = QHBoxLayout()
        self.txt_apk_path = QLineEdit()
        self.txt_apk_path.setPlaceholderText("Select or drop target .apk file...")
        self.btn_browse_apk = QPushButton("Browse")
        self.btn_browse_apk.setObjectName("SecondaryBtn")
        self.btn_browse_apk.clicked.connect(self.browse_apk)
        apk_file_layout.addWidget(self.txt_apk_path)
        apk_file_layout.addWidget(self.btn_browse_apk)
        config_layout.addLayout(apk_file_layout)
        
        # Dynamic Logs Directory
        lbl_dyn = QLabel("Dynamic Logs/Traces Folder Path (Optional)")
        lbl_dyn.setStyleSheet("font-weight: bold;")
        config_layout.addWidget(lbl_dyn)
        
        dyn_layout = QHBoxLayout()
        self.txt_dynamic_path = QLineEdit()
        self.txt_dynamic_path.setPlaceholderText("Select folder containing logcat_runtime.txt or runtime_http.txt...")
        self.btn_browse_dyn = QPushButton("Browse")
        self.btn_browse_dyn.setObjectName("SecondaryBtn")
        self.btn_browse_dyn.clicked.connect(self.browse_dyn_folder)
        dyn_layout.addWidget(self.txt_dynamic_path)
        dyn_layout.addWidget(self.btn_browse_dyn)
        config_layout.addLayout(dyn_layout)
        
        # Output Reports Directory
        lbl_out = QLabel("Output Folder (Defaults to reports/)")
        lbl_out.setStyleSheet("font-weight: bold;")
        config_layout.addWidget(lbl_out)
        
        out_layout = QHBoxLayout()
        self.txt_output_path = QLineEdit(os.path.abspath("reports"))
        self.btn_browse_out = QPushButton("Browse")
        self.btn_browse_out.setObjectName("SecondaryBtn")
        self.btn_browse_out.clicked.connect(self.browse_output_folder)
        out_layout.addWidget(self.txt_output_path)
        out_layout.addWidget(self.btn_browse_out)
        config_layout.addLayout(out_layout)
        
        # Analysis Type & Formats
        bottom_options = QHBoxLayout()
        
        # Analysis Type Selection
        type_box = QVBoxLayout()
        type_label = QLabel("Analysis Category")
        type_label.setStyleSheet("font-weight: bold; color: #10b981;")
        type_box.addWidget(type_label)
        
        self.rad_static = QRadioButton("Static Analysis Only")
        self.rad_static.setChecked(True)
        self.rad_both = QRadioButton("Static + Dynamic Correlation")
        type_box.addWidget(self.rad_static)
        type_box.addWidget(self.rad_both)
        bottom_options.addLayout(type_box, 1)
        
        # Formats Selection
        format_box = QVBoxLayout()
        format_label = QLabel("Report Formats")
        format_label.setStyleSheet("font-weight: bold; color: #10b981;")
        format_box.addWidget(format_label)
        
        self.chk_json = QCheckBox("JSON Findings Database")
        self.chk_json.setChecked(True)
        self.chk_html = QCheckBox("HTML Interactive Dashboard")
        self.chk_html.setChecked(True)
        self.chk_pdf = QCheckBox("PDF Assessment Report")
        self.chk_pdf.setChecked(True)
        
        format_box.addWidget(self.chk_json)
        format_box.addWidget(self.chk_html)
        format_box.addWidget(self.chk_pdf)
        bottom_options.addLayout(format_box, 1)
        
        config_layout.addLayout(bottom_options)
        
        # Verbose Logging
        self.chk_verbose = QCheckBox("Enable Verbose Debug Output")
        config_layout.addWidget(self.chk_verbose)
        
        # Run Button
        self.btn_run = QPushButton("START SECURITY SCAN")
        self.btn_run.setObjectName("PrimaryBtn")
        self.btn_run.clicked.connect(self.start_analysis_clicked)
        config_layout.addWidget(self.btn_run)
        
        self.main_layout.addWidget(self.config_card)
        
        # 3. Progress Card (Hidden by default)
        self.progress_card = QFrame()
        self.progress_card.setObjectName("Card")
        self.progress_card.setVisible(False)
        progress_layout = QVBoxLayout(self.progress_card)
        progress_layout.setSpacing(15)
        
        progress_title = QLabel("SCAN PERFORMANCE PROGRESS")
        progress_title.setObjectName("CardTitle")
        progress_layout.addWidget(progress_title)
        
        self.lbl_current_step = QLabel("Current Step: Idle")
        self.lbl_current_step.setStyleSheet("font-weight: bold; font-size: 14px; color: #10b981;")
        progress_layout.addWidget(self.lbl_current_step)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(20)
        progress_layout.addWidget(self.progress_bar)
        
        # Console Console logs
        self.console = QTextEdit()
        self.console.setObjectName("Console")
        self.console.setReadOnly(True)
        progress_layout.addWidget(self.console, 1)
        
        # Progress Actions
        p_actions = QHBoxLayout()
        self.btn_cancel = QPushButton("Terminate Scan")
        self.btn_cancel.setObjectName("SecondaryBtn")
        self.btn_cancel.clicked.connect(self.cancel_scan)
        
        self.btn_view_results = QPushButton("View Scan Results")
        self.btn_view_results.setObjectName("PrimaryBtn")
        self.btn_view_results.setEnabled(False)
        
        p_actions.addWidget(self.btn_cancel)
        p_actions.addWidget(self.btn_view_results)
        progress_layout.addLayout(p_actions)
        
        self.main_layout.addWidget(self.progress_card, 1)
        
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            url = event.mimeData().urls()[0].toLocalFile()
            if url.lower().endswith(".apk"):
                event.acceptProposedAction()
                
    def dropEvent(self, event: QDropEvent):
        url = event.mimeData().urls()[0].toLocalFile()
        self.txt_apk_path.setText(url)
        event.acceptProposedAction()
        
    def browse_apk(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Target APK", "", "Android Package (*.apk)")
        if file_path:
            self.txt_apk_path.setText(file_path)
            
    def browse_dyn_folder(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Runtime Logs Directory")
        if dir_path:
            self.txt_dynamic_path.setText(dir_path)
            
    def browse_output_folder(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Reports Output Directory")
        if dir_path:
            self.txt_output_path.setText(dir_path)
            
    def start_analysis_clicked(self):
        apk_path = self.txt_apk_path.text().strip()
        
        # 1. Validation
        if not apk_path:
            QMessageBox.critical(self, "Validation Error", "Target APK file path is required.")
            return
        if not os.path.exists(apk_path):
            QMessageBox.critical(self, "Validation Error", "The selected APK file path does not exist.")
            return
        if not apk_path.lower().endswith(".apk"):
            QMessageBox.critical(self, "Validation Error", "Selected file is not an .apk file.")
            return
            
        output_dir = self.txt_output_path.text().strip()
        if not output_dir:
            output_dir = "reports"
            
        # Determine dynamic analysis dir
        dynamic_dir = ""
        if self.rad_both.isChecked():
            dynamic_dir = self.txt_dynamic_path.text().strip()
            if not dynamic_dir:
                QMessageBox.warning(self, "Configuration Warning", 
                                    "Dynamic correlation requires a logs directory. Scanning in Static mode instead.")
            elif not os.path.exists(dynamic_dir):
                QMessageBox.critical(self, "Validation Error", "Selected dynamic folder does not exist.")
                return
                
        # Resolve output report file paths
        json_path = os.path.join(output_dir, "final_risk_report.json")
        html_path = os.path.join(output_dir, "report.html")
        pdf_path = os.path.join(output_dir, "report.pdf")
        
        # Clear progress UI
        self.progress_bar.setValue(0)
        self.console.clear()
        self.lbl_current_step.setText("Current Step: Initializing...")
        self.btn_view_results.setEnabled(False)
        
        # Switch widgets view
        self.config_card.setVisible(False)
        self.progress_card.setVisible(True)
        
        # Emit scan start event configurations
        self.analysis_started.emit({
            "apk_path": apk_path,
            "dynamic_dir": dynamic_dir,
            "output_dir": output_dir,
            "json_path": json_path,
            "html_path": html_path,
            "pdf_path": pdf_path,
            "verbose": self.chk_verbose.isChecked()
        })
        
    def cancel_scan(self):
        self.analysis_cancelled.emit()
        self.show_config()
        
    def show_config(self):
        self.progress_card.setVisible(False)
        self.config_card.setVisible(True)
        
    def append_log(self, text: str):
        self.console.append(text)
        
    def update_progress(self, val: int):
        self.progress_bar.setValue(val)
        
    def update_step(self, step_text: str):
        self.lbl_current_step.setText(f"Current Step: {step_text}")
        
    def set_finished(self, success: bool):
        if success:
            self.lbl_current_step.setText("Security scan completed successfully!")
            self.btn_view_results.setEnabled(True)
        else:
            self.lbl_current_step.setText("Analysis failed. See log terminal above.")
