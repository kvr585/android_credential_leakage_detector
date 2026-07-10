import os
import zipfile
import json
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QFrame, QGridLayout, QTableWidget, 
                             QTableWidgetItem, QHeaderView, QMessageBox, 
                             QScrollArea, QApplication)
from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QPixmap, QDesktopServices

class ResultsPage(QWidget):
    """
    ResultsPage displays single APK analysis results, loading reports,
    rendering visualization charts, and providing report actions.
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.report_data = {}
        self.apk_name = "N/A"
        self.output_dir = "reports"
        self.init_ui()
        
    def init_ui(self):
        # Create scroll area to accommodate charts and tables gracefully
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        self.scroll_widget = QWidget()
        scroll.setWidget(self.scroll_widget)
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(scroll)
        
        layout = QVBoxLayout(self.scroll_widget)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)
        
        # 1. Title
        title_layout = QVBoxLayout()
        self.lbl_title = QLabel("SECURITY SCAN RESULTS")
        self.lbl_title.setStyleSheet("font-size: 26px; font-weight: bold; color: #10b981;")
        self.lbl_subtitle = QLabel("Overview of detected credential leakages and security vulnerabilities.")
        self.lbl_subtitle.setStyleSheet("color: #94a3b8; font-size: 14px;")
        title_layout.addWidget(self.lbl_title)
        title_layout.addWidget(self.lbl_subtitle)
        layout.addLayout(title_layout)
        
        # 2. Stats Grid
        stats_layout = QGridLayout()
        stats_layout.setSpacing(15)
        
        self.card_risk = self.create_result_card("OVERALL RISK PROFILE", "N/A")
        self.card_score = self.create_result_card("OVERALL RISK SCORE", "0.0")
        self.card_static_cnt = self.create_result_card("STATIC CODE FINDINGS", "0")
        self.card_dynamic_cnt = self.create_result_card("DYNAMIC RUNTIME FINDINGS", "0")
        
        stats_layout.addWidget(self.card_risk, 0, 0)
        stats_layout.addWidget(self.card_score, 0, 1)
        stats_layout.addWidget(self.card_static_cnt, 0, 2)
        stats_layout.addWidget(self.card_dynamic_cnt, 0, 3)
        layout.addLayout(stats_layout)
        
        # Executive Summary Label
        self.lbl_exec_summary = QLabel("Analysis Executive Summary details...")
        self.lbl_exec_summary.setStyleSheet("color: #cbd5e1; font-size: 14px; padding: 15px; background-color: #1e293b; border-radius: 8px; border-left: 4px solid #10b981;")
        self.lbl_exec_summary.setWordWrap(True)
        layout.addWidget(self.lbl_exec_summary)
        
        # 3. Charts Area
        charts_layout = QHBoxLayout()
        charts_layout.setSpacing(20)
        
        # Pie Chart Frame
        self.pie_frame = QFrame()
        self.pie_frame.setObjectName("Card")
        pie_lay = QVBoxLayout(self.pie_frame)
        pie_title = QLabel("SEVERITY DISTRIBUTION")
        pie_title.setObjectName("CardTitle")
        self.lbl_pie_img = QLabel()
        self.lbl_pie_img.setAlignment(Qt.AlignCenter)
        pie_lay.addWidget(pie_title)
        pie_lay.addWidget(self.lbl_pie_img)
        
        # Bar Chart Frame
        self.bar_frame = QFrame()
        self.bar_frame.setObjectName("Card")
        bar_lay = QVBoxLayout(self.bar_frame)
        bar_title = QLabel("VULNERABILITY CATEGORY DISTRIBUTION")
        bar_title.setObjectName("CardTitle")
        self.lbl_bar_img = QLabel()
        self.lbl_bar_img.setAlignment(Qt.AlignCenter)
        bar_lay.addWidget(bar_title)
        bar_lay.addWidget(self.lbl_bar_img)
        
        charts_layout.addWidget(self.pie_frame, 1)
        charts_layout.addWidget(self.bar_frame, 1)
        layout.addLayout(charts_layout)
        
        # 4. Recommendations Table
        recs_card = QFrame()
        recs_card.setObjectName("Card")
        recs_layout = QVBoxLayout(recs_card)
        recs_layout.setSpacing(10)
        
        recs_title = QLabel("VULNERABILITY REMEDIATION ACTION PLAN")
        recs_title.setObjectName("CardTitle")
        recs_layout.addWidget(recs_title)
        
        self.table_recs = QTableWidget(0, 3)
        self.table_recs.setHorizontalHeaderLabels(["Security Category", "OWASP Mapping", "Remediation Recommendation"])
        self.table_recs.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_recs.setAlternatingRowColors(True)
        self.table_recs.verticalHeader().setVisible(False)
        self.table_recs.setStyleSheet("QTableWidget { border: none; background-color: transparent; }")
        recs_layout.addWidget(self.table_recs)
        
        layout.addWidget(recs_card)
        
        # 5. Report Buttons / Actions
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)
        
        btn_json = QPushButton("Open JSON Findings")
        btn_json.setObjectName("SecondaryBtn")
        btn_json.clicked.connect(self.open_json_report)
        
        btn_html = QPushButton("Open HTML Dashboard")
        btn_html.setObjectName("SecondaryBtn")
        btn_html.clicked.connect(self.open_html_report)
        
        btn_pdf = QPushButton("Open PDF Assessment")
        btn_pdf.setObjectName("SecondaryBtn")
        btn_pdf.clicked.connect(self.open_pdf_report)
        
        btn_zip = QPushButton("Export ZIP Archive")
        btn_zip.setObjectName("SecondaryBtn")
        btn_zip.clicked.connect(self.export_zip_archive)
        
        btn_copy = QPushButton("Copy Security Summary")
        btn_copy.setObjectName("PrimaryBtn")
        btn_copy.clicked.connect(self.copy_to_clipboard)
        
        btn_layout.addWidget(btn_json)
        btn_layout.addWidget(btn_html)
        btn_layout.addWidget(btn_pdf)
        btn_layout.addWidget(btn_zip)
        btn_layout.addWidget(btn_copy)
        
        layout.addLayout(btn_layout)
        
    def create_result_card(self, title: str, val: str) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        lay = QVBoxLayout(card)
        lay.setAlignment(Qt.AlignCenter)
        lay.setSpacing(5)
        
        lbl = QLabel(title)
        lbl.setStyleSheet("font-size: 11px; font-weight: bold; color: #94a3b8;")
        val_lbl = QLabel(val)
        val_lbl.setStyleSheet("font-size: 20px; font-weight: 800; color: #10b981;")
        
        lay.addWidget(lbl, 0, Qt.AlignCenter)
        lay.addWidget(val_lbl, 0, Qt.AlignCenter)
        card.setProperty("val_widget", val_lbl)
        return card
        
    def display_results(self, data: dict, apk_path: str, output_dir: str):
        """Displays data in labels, tables, and loads Matplotlib charts."""
        self.report_data = data
        self.apk_name = os.path.basename(apk_path)
        self.output_dir = output_dir
        
        # 1. Update title info
        self.lbl_title.setText(f"SECURITY SCAN RESULTS: {self.apk_name}")
        
        # 2. Update Stats
        risk_rating = data.get("overall_risk", "INFO")
        risk_score = data.get("overall_risk_score", 0.0)
        
        self.card_risk.property("val_widget").setText(str(risk_rating))
        self.card_score.property("val_widget").setText(f"{risk_score:.2f}")
        self.card_static_cnt.property("val_widget").setText(str(data.get("static_findings_count", 0)))
        
        dyn_cnt = data.get("dynamic_logcat_findings_count", 0) + data.get("dynamic_network_findings_count", 0)
        self.card_dynamic_cnt.property("val_widget").setText(str(dyn_cnt))
        
        # Color coding risk label
        lbl_risk = self.card_risk.property("val_widget")
        color_map = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#f59e0b",
            "LOW": "#3b82f6",
            "INFO": "#10b981"
        }
        lbl_risk.setStyleSheet(f"font-size: 20px; font-weight: 800; color: {color_map.get(risk_rating.upper(), '#10b981')};")
        
        # Executive Summary
        self.lbl_exec_summary.setText(data.get("executive_summary", "No details available."))
        
        # 3. Load Charts
        self.load_visualization_charts()
        
        # 4. Load Recommendations Table
        recs = data.get("recommendations", [])
        self.table_recs.setRowCount(0)
        for idx, r in enumerate(recs):
            self.table_recs.insertRow(idx)
            self.table_recs.setItem(idx, 0, QTableWidgetItem(r.get("category", "N/A")))
            self.table_recs.setItem(idx, 1, QTableWidgetItem(f"OWASP {r.get('owasp', 'N/A')}"))
            self.table_recs.setItem(idx, 2, QTableWidgetItem(r.get("recommendation", "N/A")))
            
    def load_visualization_charts(self):
        """Loads matplotlib PNG files if available."""
        pie_path = os.path.join(self.output_dir, "severity_pie.png")
        bar_path = os.path.join(self.output_dir, "category_bar.png")
        
        if os.path.exists(pie_path):
            pix = QPixmap(pie_path)
            self.lbl_pie_img.setPixmap(pix.scaled(400, 320, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        else:
            self.lbl_pie_img.setText("[Chart unavailable]")
            
        if os.path.exists(bar_path):
            pix = QPixmap(bar_path)
            self.lbl_bar_img.setPixmap(pix.scaled(400, 320, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        else:
            self.lbl_bar_img.setText("[Chart unavailable]")
            
    def open_json_report(self):
        json_path = os.path.abspath(os.path.join(self.output_dir, "final_risk_report.json"))
        if os.path.exists(json_path):
            QDesktopServices.openUrl(QUrl.fromLocalFile(json_path))
        else:
            QMessageBox.warning(self, "File Not Found", "JSON findings report does not exist.")
            
    def open_html_report(self):
        html_path = os.path.abspath(os.path.join(self.output_dir, "report.html"))
        if os.path.exists(html_path):
            QDesktopServices.openUrl(QUrl.fromLocalFile(html_path))
        else:
            QMessageBox.warning(self, "File Not Found", "HTML findings dashboard does not exist.")
            
    def open_pdf_report(self):
        pdf_path = os.path.abspath(os.path.join(self.output_dir, "report.pdf"))
        if os.path.exists(pdf_path):
            QDesktopServices.openUrl(QUrl.fromLocalFile(pdf_path))
        else:
            QMessageBox.warning(self, "File Not Found", "PDF findings report does not exist.")
            
    def export_zip_archive(self):
        """Creates a ZIP archive containing all reports and charts."""
        zip_path, _ = QFileDialog.getSaveFileName(self, "Save ZIP Archive", "", "ZIP Archives (*.zip)")
        if not zip_path:
            return
            
        try:
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zip_f:
                for root, _, files in os.walk(self.output_dir):
                    for file in files:
                        if file.endswith((".json", ".html", ".pdf", ".png")):
                            full_path = os.path.join(root, file)
                            arcname = os.path.relpath(full_path, self.output_dir)
                            zip_f.write(full_path, arcname)
            QMessageBox.information(self, "Export Success", f"ZIP archive exported to:\n{zip_path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Failed to export ZIP archive: {e}")
            
    def copy_to_clipboard(self):
        """Copies a structured summary to the clipboard."""
        summary = (
            f"=== SECURITY ASSESSMENT SUMMARY ===\n"
            f"Target APK: {self.apk_name}\n"
            f"Overall Risk Profile: {self.report_data.get('overall_risk', 'INFO')}\n"
            f"Risk Score: {self.report_data.get('overall_risk_score', 0.0):.2f}/100\n"
            f"Static Code Findings: {self.report_data.get('static_findings_count', 0)}\n"
            f"Dynamic Runtime Leaks: {self.report_data.get('dynamic_logcat_findings_count', 0) + self.report_data.get('dynamic_network_findings_count', 0)}\n\n"
            f"Detailed Reasoning:\n"
            + "\n".join([f"- {r}" for r in self.report_data.get('risk_reasoning', [])])
        )
        QApplication.clipboard().setText(summary)
        QMessageBox.information(self, "Copy Success", "Assessment summary copied to clipboard.")
