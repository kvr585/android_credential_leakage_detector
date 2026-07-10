import os
import sys
import json
from PySide6.QtCore import QObject, Signal, QProcess

class SecurityProcessWorker(QObject):
    """
    Manages background process execution for APK analysis or comparison.
    Uses QProcess to capture live console output and trigger progress updates.
    """
    log_received = Signal(str)
    step_changed = Signal(str)
    progress_changed = Signal(int)
    finished = Signal(bool, dict)  # (success, result_data)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.process = None
        self.output_json_path = ""
        self.is_compare_mode = False
        
    def start_analysis(self, apk_path: str, dynamic_dir: str, output_dir: str, 
                       json_path: str, html_path: str, pdf_path: str, 
                       verbose: bool):
        """Launches single APK analysis via QProcess."""
        self.is_compare_mode = False
        self.output_json_path = json_path
        
        self.process = QProcess(self)
        self.process.readyReadStandardOutput.connect(self.handle_stdout)
        self.process.readyReadStandardError.connect(self.handle_stderr)
        self.process.finished.connect(self.handle_finished)
        
        # Build command-line arguments using system python interpreter
        python_exe = sys.executable if sys.executable else "python3"
        main_py = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "main.py"))
        
        args = [main_py, apk_path]
        if dynamic_dir:
            args.append(dynamic_dir)
            
        args.extend(["--json", json_path])
        args.extend(["--html", html_path])
        args.extend(["--pdf", pdf_path])
        args.extend(["--output", output_dir])
        if verbose:
            args.append("--verbose")
            
        self.log_received.emit(f"[SYSTEM] Executing: {python_exe} " + " ".join(args))
        self.process.start(python_exe, args)
        
    def start_comparison(self, old_apk: str, new_apk: str, dynamic_dir: str, 
                         output_dir: str, verbose: bool):
        """Launches APK comparison via QProcess."""
        self.is_compare_mode = True
        self.output_json_path = os.path.join(output_dir, "comparison_report.json")
        
        self.process = QProcess(self)
        self.process.readyReadStandardOutput.connect(self.handle_stdout)
        self.process.readyReadStandardError.connect(self.handle_stderr)
        self.process.finished.connect(self.handle_finished)
        
        python_exe = sys.executable if sys.executable else "python3"
        main_py = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "main.py"))
        
        args = [main_py, "--compare", old_apk, new_apk]
        if dynamic_dir:
            args.extend(["--dynamic", dynamic_dir])
            
        args.extend(["--output", output_dir])
        if verbose:
            args.append("--verbose")
            
        self.log_received.emit(f"[SYSTEM] Executing: {python_exe} " + " ".join(args))
        self.process.start(python_exe, args)
        
    def handle_stdout(self):
        """Reads stdout from QProcess and parses log patterns for progress."""
        data = self.process.readAllStandardOutput().data().decode("utf-8", errors="ignore")
        for line in data.splitlines():
            line_str = line.strip()
            if not line_str:
                continue
            self.log_received.emit(line_str)
            self.parse_progress_milestones(line_str)
            
    def handle_stderr(self):
        """Reads stderr from QProcess."""
        data = self.process.readAllStandardError().data().decode("utf-8", errors="ignore")
        for line in data.splitlines():
            line_str = line.strip()
            if line_str:
                self.log_received.emit(f"[ERROR] {line_str}")
                
    def parse_progress_milestones(self, line: str):
        """Maps print outputs to progress bar values and steps."""
        if "Initializing system frameworks" in line:
            self.step_changed.emit("Initializing System...")
            self.progress_changed.emit(10)
        elif "[+] Decompiling APK" in line:
            self.step_changed.emit("Decompiling APK via APKTool...")
            self.progress_changed.emit(25)
        elif "[+] Strings extracted" in line:
            self.step_changed.emit("Extracting Strings...")
            self.progress_changed.emit(45)
        elif "Running static analysis" in line:
            self.step_changed.emit("Running Static Rule Engine...")
            self.progress_changed.emit(60)
        elif "Parsing runtime logcat" in line or "Parsing network" in line:
            self.step_changed.emit("Parsing Dynamic Traces...")
            self.progress_changed.emit(75)
        elif "Correlating findings" in line:
            self.step_changed.emit("Correlating Findings...")
            self.progress_changed.emit(85)
        elif "Writing PDF report" in line or "Writing HTML report" in line:
            self.step_changed.emit("Generating Reports & Visualizations...")
            self.progress_changed.emit(95)
            
    def handle_finished(self, exit_code: int):
        """Reads resulting JSON when QProcess finishes."""
        success = (exit_code == 0)
        result_data = {}
        
        if success and os.path.exists(self.output_json_path):
            try:
                with open(self.output_json_path, "r", encoding="utf-8") as f:
                    result_data = json.load(f)
            except Exception as e:
                self.log_received.emit(f"[ERROR] Failed to parse output JSON: {e}")
                success = False
        else:
            self.log_received.emit(f"[SYSTEM] Process finished with exit code {exit_code}")
            
        self.progress_changed.emit(100)
        self.finished.emit(success, result_data)
        
    def terminate(self):
        """Terminates the running process if necessary."""
        if self.process and self.process.state() == QProcess.ProcessState.Running:
            self.process.terminate()
            self.process.waitForFinished(1000)
            self.log_received.emit("[SYSTEM] Analysis process terminated by user.")
