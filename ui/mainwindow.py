import os
import json
import datetime
from PySide6.QtWidgets import (QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, 
                             QFrame, QPushButton, QStackedWidget, QLabel, 
                             QMessageBox, QTableWidget, QTableWidgetItem, 
                             QHeaderView, QListWidget, QListWidgetItem)
from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices, QIcon

# Page imports
from ui.dashboard import DashboardPage
from ui.analyze import AnalyzePage
from ui.compare import ComparePage
from ui.results import ResultsPage
from ui.settings import SettingsPage
from ui.about import AboutPage
from ui.theme import get_stylesheet
from ui.workers import SecurityProcessWorker

class ReportsPage(QWidget):
    """
    ReportsPage displays all generated reports in the output directory
    and provides actions to open them directly.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.output_dir = "reports"
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        # Header
        header = QVBoxLayout()
        title = QLabel("GENERATED REPORTS ARCHIVE")
        title.setStyleSheet("font-size: 26px; font-weight: bold; color: #10b981;")
        subtitle = QLabel("Browse and inspect all compiled assessment outputs.")
        subtitle.setStyleSheet("color: #94a3b8; font-size: 14px;")
        header.addWidget(title)
        header.addWidget(subtitle)
        layout.addLayout(header)
        
        # List Card
        list_card = QFrame()
        list_card.setObjectName("Card")
        list_layout = QVBoxLayout(list_card)
        
        lbl_list = QLabel("REPORTS IN OUTPUT DIRECTORY")
        lbl_list.setObjectName("CardTitle")
        list_layout.addWidget(lbl_list)
        
        self.reports_list = QListWidget()
        self.reports_list.setStyleSheet("QListWidget { border: none; background-color: transparent; font-size: 14px; }")
        self.reports_list.itemDoubleClicked.connect(self.open_selected_report)
        list_layout.addWidget(self.reports_list)
        
        # Actions
        actions_lay = QHBoxLayout()
        btn_open = QPushButton("Open Selected Document")
        btn_open.setObjectName("PrimaryBtn")
        btn_open.clicked.connect(lambda: self.open_selected_report(self.reports_list.currentItem()))
        
        btn_refresh = QPushButton("Refresh List")
        btn_refresh.setObjectName("SecondaryBtn")
        btn_refresh.clicked.connect(self.refresh_list)
        
        actions_lay.addWidget(btn_open)
        actions_lay.addWidget(btn_refresh)
        list_layout.addLayout(actions_lay)
        
        layout.addWidget(list_card)
        self.refresh_list()
        
    def refresh_list(self):
        self.reports_list.clear()
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)
            
        try:
            for file in sorted(os.listdir(self.output_dir)):
                if file.endswith((".json", ".html", ".pdf")):
                    item = QListWidgetItem(file)
                    # Add simple icons depending on file type
                    self.reports_list.addItem(item)
        except Exception as e:
            print(f"[ERROR] Failed to list reports folder: {e}")
            
    def open_selected_report(self, item):
        if not item:
            QMessageBox.warning(self, "No Selection", "Please select a report file to open.")
            return
        file_path = os.path.abspath(os.path.join(self.output_dir, item.text()))
        if os.path.exists(file_path):
            QDesktopServices.openUrl(QUrl.fromLocalFile(file_path))
        else:
            QMessageBox.warning(self, "File Not Found", "The selected file no longer exists.")

class HistoryPage(QWidget):
    """
    HistoryPage displays historical records of single APK analysis runs,
    reading from reports/history.json.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        # Header
        header = QVBoxLayout()
        title = QLabel("SCAN CHRONOLOGICAL HISTORY")
        title.setStyleSheet("font-size: 26px; font-weight: bold; color: #10b981;")
        subtitle = QLabel("Displaying the latest 20 security scans and assessments.")
        subtitle.setStyleSheet("color: #94a3b8; font-size: 14px;")
        header.addWidget(title)
        header.addWidget(subtitle)
        layout.addLayout(header)
        
        # Table Card
        table_card = QFrame()
        table_card.setObjectName("Card")
        table_lay = QVBoxLayout(table_card)
        
        table_title = QLabel("SCAN HISTORY RECORDS")
        table_title.setObjectName("CardTitle")
        table_lay.addWidget(table_title)
        
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["APK Target Name", "Analysis Date", "Risk Rating", "Risk Score", "Operation Status"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setStyleSheet("QTableWidget { border: none; background-color: transparent; }")
        table_lay.addWidget(self.table)
        
        btn_refresh = QPushButton("Refresh History Table")
        btn_refresh.setObjectName("SecondaryBtn")
        btn_refresh.clicked.connect(self.refresh_history)
        table_lay.addWidget(btn_refresh)
        
        layout.addWidget(table_card)
        self.refresh_history()
        
    def refresh_history(self):
        self.table.setRowCount(0)
        history_path = os.path.join("reports", "history.json")
        scans = []
        
        if os.path.exists(history_path):
            try:
                with open(history_path, "r", encoding="utf-8") as f:
                    scans = json.load(f)
            except Exception:
                pass
                
        # Get latest 20 scans in reverse chronological order
        display_scans = scans[-20:][::-1]
        for idx, scan in enumerate(display_scans):
            self.table.insertRow(idx)
            self.table.setItem(idx, 0, QTableWidgetItem(scan.get("apk_name", "N/A")))
            self.table.setItem(idx, 1, QTableWidgetItem(scan.get("date", "N/A")))
            self.table.setItem(idx, 2, QTableWidgetItem(scan.get("risk", "INFO")))
            self.table.setItem(idx, 3, QTableWidgetItem(f"{scan.get('score', 0.0):.2f}"))
            self.table.setItem(idx, 4, QTableWidgetItem(scan.get("status", "SUCCESS")))

class MainWindow(QMainWindow):
    """
    MainWindow serves as the principal PySide6 UI window shell, orchestrating
    sidebar navigation, stacked views, QProcess background workers, and stylesheets.
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Android Credential Leakage Detection System V2")
        self.resize(1400, 850)
        self.init_ui()
        
        # Load user configurations
        self.load_application_settings()
        
        # Initialize background worker
        self.worker = SecurityProcessWorker(self)
        self.worker.log_received.connect(self.handle_worker_log)
        self.worker.step_changed.connect(self.handle_worker_step)
        self.worker.progress_changed.connect(self.handle_worker_progress)
        self.worker.finished.connect(self.handle_worker_finished)
        
    def init_ui(self):
        # 1. Central Widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        main_layout = QHBoxLayout(self.central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # 2. Sidebar QFrame
        self.sidebar = QFrame()
        self.sidebar.setObjectName("Sidebar")
        self.sidebar.setFixedWidth(240)
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(15, 30, 15, 30)
        sidebar_layout.setSpacing(10)
        
        # Sidebar Logo/Header
        lbl_logo = QLabel("ACLD SYSTEM V2")
        lbl_logo.setStyleSheet("font-size: 18px; font-weight: 800; color: #10b981; padding-bottom: 20px;")
        lbl_logo.setAlignment(Qt.AlignCenter)
        sidebar_layout.addWidget(lbl_logo)
        
        # Sidebar Buttons Group
        self.nav_buttons = []
        menu_items = [
            ("Dashboard", 0),
            ("Analyze APK", 1),
            ("Compare APKs", 2),
            ("Reports Archive", 3),
            ("Scan History", 4),
            ("Settings", 5),
            ("About", 6)
        ]
        
        for name, idx in menu_items:
            btn = QPushButton(name)
            btn.setObjectName("SidebarBtn")
            btn.setCheckable(True)
            btn.setAutoExclusive(True)
            btn.clicked.connect(lambda checked, i=idx: self.switch_page(i))
            sidebar_layout.addWidget(btn)
            self.nav_buttons.append(btn)
            
        # Check Dashboard by default
        self.nav_buttons[0].setChecked(True)
        sidebar_layout.addStretch()
        
        # Footer
        lbl_footer = QLabel("Parul University Capstone")
        lbl_footer.setStyleSheet("color: #64748b; font-size: 11px;")
        lbl_footer.setAlignment(Qt.AlignCenter)
        sidebar_layout.addWidget(lbl_footer)
        
        main_layout.addWidget(self.sidebar)
        
        # 3. Stacked Pages Widget
        self.stacked_widget = QStackedWidget()
        
        # Page Instantiations
        self.page_dashboard = DashboardPage()
        self.page_analyze = AnalyzePage()
        self.page_compare = ComparePage()
        self.page_reports = ReportsPage()
        self.page_history = HistoryPage()
        self.page_settings = SettingsPage()
        self.page_about = AboutPage()
        self.page_results = ResultsPage()  # Separate Results view page index 7
        
        self.stacked_widget.addWidget(self.page_dashboard)  # Index 0
        self.stacked_widget.addWidget(self.page_analyze)    # Index 1
        self.stacked_widget.addWidget(self.page_compare)    # Index 2
        self.stacked_widget.addWidget(self.page_reports)    # Index 3
        self.stacked_widget.addWidget(self.page_history)    # Index 4
        self.stacked_widget.addWidget(self.page_settings)    # Index 5
        self.stacked_widget.addWidget(self.page_about)       # Index 6
        self.stacked_widget.addWidget(self.page_results)     # Index 7
        
        main_layout.addWidget(self.stacked_widget, 1)
        
        # Connections
        self.page_dashboard.navigate_to_page.connect(self.switch_page)
        self.page_analyze.analysis_started.connect(self.start_worker_analysis)
        self.page_analyze.analysis_cancelled.connect(self.cancel_worker_task)
        self.page_analyze.btn_view_results.clicked.connect(self.show_results_page)
        self.page_compare.comparison_started.connect(self.start_worker_comparison)
        self.page_compare.comparison_cancelled.connect(self.cancel_worker_task)
        self.page_settings.settings_changed.connect(self.apply_theme_settings)
        
    def switch_page(self, index: int):
        """Changes stacked widget active page and handles navigation highlighting."""
        # Uncheck results button highlighting if switching to standard tabs
        if index < len(self.nav_buttons):
            self.nav_buttons[index].setChecked(True)
            
        # Refresh dynamic page lists
        if index == 0:
            self.page_dashboard.refresh_data()
        elif index == 3:
            self.page_reports.refresh_list()
        elif index == 4:
            self.page_history.refresh_history()
            
        self.stacked_widget.setCurrentIndex(index)
        
    def load_application_settings(self):
        """Loads local settings and sets initial stylesheets."""
        settings = self.page_settings.load_settings()
        self.apply_theme_settings(settings)
        
    def apply_theme_settings(self, settings: dict):
        """Applies chosen style settings (Dark, Light, Cyber Green)."""
        theme_name = settings.get("theme", "Dark")
        stylesheet_str = get_stylesheet(theme_name)
        self.setStyleSheet(stylesheet_str)
        
        # Apply output directories to folders
        default_dir = settings.get("default_output_dir", "reports")
        self.page_reports.output_dir = default_dir
        self.page_analyze.txt_output_path.setText(default_dir)
        self.page_compare.txt_output_path.setText(default_dir)
        
    # --- Background Process Thread Handlers ---
    
    def start_worker_analysis(self, config: dict):
        self.current_apk_path = config["apk_path"]
        self.current_output_dir = config["output_dir"]
        self.current_json_path = config["json_path"]
        
        self.worker.start_analysis(
            apk_path=config["apk_path"],
            dynamic_dir=config["dynamic_dir"],
            output_dir=config["output_dir"],
            json_path=config["json_path"],
            html_path=config["html_path"],
            pdf_path=config["pdf_path"],
            verbose=config["verbose"]
        )
        
    def start_worker_comparison(self, config: dict):
        self.current_apk_path = config["new_apk"]
        self.current_output_dir = config["output_dir"]
        
        self.worker.start_comparison(
            old_apk=config["old_apk"],
            new_apk=config["new_apk"],
            dynamic_dir=config["dynamic_dir"],
            output_dir=config["output_dir"],
            verbose=config["verbose"]
        )
        
    def cancel_worker_task(self):
        self.worker.terminate()
        
    def handle_worker_log(self, text: str):
        if self.worker.is_compare_mode:
            self.page_compare.append_log(text)
        else:
            self.page_analyze.append_log(text)
            
    def handle_worker_step(self, step_text: str):
        if self.worker.is_compare_mode:
            self.page_compare.update_step(step_text)
        else:
            self.page_analyze.update_step(step_text)
            
    def handle_worker_progress(self, val: int):
        if self.worker.is_compare_mode:
            self.page_compare.update_progress(val)
        else:
            self.page_analyze.update_progress(val)
            
    def handle_worker_finished(self, success: bool, data: dict):
        if self.worker.is_compare_mode:
            self.page_compare.set_finished(success)
            if success:
                self.page_compare.display_results(data)
            else:
                QMessageBox.critical(self, "Comparison Failed", "APK posture comparison failed. Review logs.")
        else:
            self.page_analyze.set_finished(success)
            if success:
                # Save scan history
                self.save_scan_history(
                    apk_name=os.path.basename(self.current_apk_path),
                    risk=data.get("overall_risk", "INFO"),
                    score=data.get("overall_risk_score", 0.0)
                )
                # Load findings directly inside Results Page view
                self.page_results.display_results(data, self.current_apk_path, self.current_output_dir)
            else:
                QMessageBox.critical(self, "Analysis Failed", "Vulnerability analysis scan failed. Review logs.")
                
    def show_results_page(self):
        self.switch_page(7) # Results page index is 7
        
    def save_scan_history(self, apk_name: str, risk: str, score: float):
        """Appends a new scan run entry in the local reports/history.json file."""
        history_dir = "reports"
        os.makedirs(history_dir, exist_ok=True)
        history_path = os.path.join(history_dir, "history.json")
        
        scans = []
        if os.path.exists(history_path):
            try:
                with open(history_path, "r", encoding="utf-8") as f:
                    scans = json.load(f)
            except Exception:
                pass
                
        new_entry = {
            "apk_name": apk_name,
            "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "risk": risk,
            "score": score,
            "status": "SUCCESS"
        }
        scans.append(new_entry)
        
        # Bound size to latest 50 logs
        scans = scans[-50:]
        
        try:
            with open(history_path, "w", encoding="utf-8") as f:
                json.dump(scans, f, indent=2)
        except Exception as e:
            print(f"[ERROR] Failed to save scan history: {e}")
            
    def closeEvent(self, event):
        """Ensures running background processes are cleaned up upon application close."""
        self.worker.terminate()
        event.accept()
