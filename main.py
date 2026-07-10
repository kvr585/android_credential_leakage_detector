import os
import sys
import json
import time
import argparse
import webbrowser
from tabulate import tabulate
from typing import Dict, Any, List

# Centralized version import
from __version__ import VERSION

# Project modules
from static_analysis.analyze_apk import run_static
from dynamic_analysis.parse_logcat import parse_logcat
from dynamic_analysis.parse_pcap import parse_pcap
from correlation.correlation import correlate, compare_reports
from utils.logger import setup_logger
from utils.report_generator import generate_html_report, generate_pdf_report

def analyze_single_apk(apk_path: str, dynamic_dir: str, logger) -> Dict[str, Any]:
    """
    Executes the analysis pipeline on a single APK and returns the correlated report dictionary.
    """
    logger.info(f"Starting analysis for: {apk_path}")
    start_time = time.time()
    
    # 1. Static Analysis
    logger.info("Running static analysis decompilation and string extraction...")
    static_results = run_static(apk_path)
    logger.info(f"Static analysis complete. Found {len(static_results)} static findings.")

    # 2. Dynamic Analysis
    logcat_results = []
    network_results = []
    
    if dynamic_dir:
        logcat_path = os.path.join(dynamic_dir, "logcat_runtime.txt")
        pcap_path = os.path.join(dynamic_dir, "runtime_http.txt")

        logger.info(f"Checking for runtime dynamic traces in: {dynamic_dir}")
        if os.path.exists(logcat_path):
            logger.info("Parsing runtime logcat logs...")
            logcat_results = parse_logcat(logcat_path)
            logger.info(f"Parsed {len(logcat_results)} logcat leakages.")
        else:
            logger.warning(f"Logcat runtime file not found: {logcat_path}")

        if os.path.exists(pcap_path):
            logger.info("Parsing network captures...")
            network_results = parse_pcap(pcap_path)
            logger.info(f"Parsed {len(network_results)} network leakages.")
        else:
            logger.warning(f"Network capture file not found: {pcap_path}")
    else:
        logger.info("Dynamic analysis directory not supplied. Skipping dynamic checks.")

    # 3. Correlation & Risk Scoring
    logger.info("Correlating findings and calculating weighted risk scores...")
    report_json_str = correlate(static_results, logcat_results, network_results)
    report_data = json.loads(report_json_str)
    
    duration = time.time() - start_time
    logger.info(f"Analysis completed in {duration:.2f} seconds.")
    
    return report_data

def launch_gui_app():
    """Imports gui module and runs its main event loop."""
    print("[SYSTEM] Starting PySide6 Graphical User Interface...")
    try:
        import gui
        gui.main()
    except ImportError as e:
        print(f"[!] PySide6 GUI dependencies are not installed correctly: {e}")
        print("[!] Please run: pip install -e .")
    except Exception as e:
        print(f"[!] Error launching GUI: {e}")

def view_interactive_reports():
    """CLI Menu to browse and open generated reports."""
    output_dir = "reports"
    if not os.path.exists(output_dir):
        print("[!] Reports directory does not exist yet. Run a scan first.")
        return
        
    files = sorted([f for f in os.listdir(output_dir) if f.endswith((".json", ".html", ".pdf"))])
    if not files:
        print("[!] No report files found in reports/ directory.")
        return
        
    print("\n================ COMPLED REPORT ARCHIVE ================")
    for idx, f in enumerate(files):
        print(f"{idx+1}. {f}")
    print("0. Back to main menu")
    print("========================================================")
    
    try:
        choice = input("Select report file index to open: ").strip()
    except (KeyboardInterrupt, EOFError):
        return
        
    if choice == "0" or not choice:
        return
        
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(files):
            file_path = os.path.abspath(os.path.join(output_dir, files[idx]))
            print(f"[+] Opening {files[idx]} in your system default viewer...")
            webbrowser.open("file://" + file_path)
        else:
            print("[!] Invalid index selection.")
    except ValueError:
        print("[!] Invalid choice. Please enter a valid number.")

def show_scan_history_cli():
    """Prints previous scans history from history.json in a terminal table."""
    history_path = os.path.join("reports", "history.json")
    if not os.path.exists(history_path):
        print("[!] No scan history records found.")
        return
        
    try:
        with open(history_path, "r", encoding="utf-8") as f:
            scans = json.load(f)
    except Exception as e:
        print(f"[!] Failed to read history: {e}")
        return
        
    if not scans:
        print("[!] Scan history is empty.")
        return
        
    table_rows = []
    # Show latest 20 scans in reverse chronological order
    for scan in scans[-20:][::-1]:
        table_rows.append([
            scan.get("apk_name", "N/A"),
            scan.get("date", "N/A"),
            scan.get("risk", "INFO"),
            f"{scan.get('score', 0.0):.2f}",
            scan.get("status", "SUCCESS")
        ])
        
    print("\n================ SYSTEM SCAN HISTORY ================")
    print(
        tabulate(
            table_rows,
            headers=["APK Target Name", "Scan Date/Time", "Risk Rating", "Risk Score", "Status"],
            tablefmt="fancy_grid"
        )
    )

def open_reports_folder_shell():
    """Opens reports output folder using default file explorer."""
    reports_dir = os.path.abspath("reports")
    os.makedirs(reports_dir, exist_ok=True)
    print(f"[+] Opening directory: {reports_dir}")
    webbrowser.open("file://" + reports_dir)

def configure_interactive_settings():
    """Simple CLI menu to change configurations."""
    settings_file = "settings.json"
    config = {"theme": "Dark", "default_output_dir": os.path.abspath("reports"), "verbose_logging": False}
    
    if os.path.exists(settings_file):
        try:
            with open(settings_file, "r", encoding="utf-8") as f:
                config = json.load(f)
        except:
            pass
            
    print("\n================ SYSTEM CONFIGURATIONS ================")
    print(f"1. Current Theme : {config.get('theme', 'Dark')}")
    print(f"2. Output Folder : {config.get('default_output_dir', 'reports')}")
    print(f"3. Debug Logging : {'Enabled' if config.get('verbose_logging') else 'Disabled'}")
    print("0. Back to main menu")
    print("=======================================================")
    
    try:
        choice = input("Select setting to modify: ").strip()
    except (KeyboardInterrupt, EOFError):
        return
        
    if choice == "1":
        theme_val = input("Enter theme name (Dark / Light / Cyber Green): ").strip()
        if theme_val in ["Dark", "Light", "Cyber Green"]:
            config["theme"] = theme_val
            print(f"[+] Theme changed to {theme_val}")
    elif choice == "2":
        path_val = input("Enter default output folder path: ").strip()
        if path_val:
            config["default_output_dir"] = os.path.abspath(path_val)
            print(f"[+] Output folder changed to {config['default_output_dir']}")
    elif choice == "3":
        config["verbose_logging"] = not config.get("verbose_logging", False)
        print(f"[+] Debug Logging is now {'Enabled' if config['verbose_logging'] else 'Disabled'}")
        
    try:
        with open(settings_file, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        print(f"[!] Failed to write settings: {e}")

def print_about_details():
    print("""
================ PROJECT SPECIFICATIONS ================
Framework   : Android Credential Leakage Detection System V2
Version     : 2.0.0
License     : MIT Academic License
Developer   : Veera bhadhra
Supervisor  : Capstone Committee Panel
University  : Parul University

Paper Title : Automated Static and Dynamic Risk-Weighted Android Credential
              Leakage Detection Framework
=========================================================
""")

GREEN = "\033[1;32m"
CYAN = "\033[1;36m"
YELLOW = "\033[1;33m"
RED = "\033[1;31m"
RESET = "\033[0m"

BANNER = f"""{CYAN}
 █████╗  ██████╗██╗     ██████╗ ███████╗
██╔══██╗██╔════╝██║     ██╔══██╗██╔════╝
███████║██║     ██║     ██║  ██║███████╗
██╔══██║██║     ██║     ██║  ██║╚════██║
██║  ██║╚██████╗███████╗██████╔╝███████║
╚═╝  ╚═╝ ╚═════╝╚══════╝╚═════╝ ╚══════╝
{GREEN}
Android Credential Leakage Detection System
Version {VERSION}
{RESET}"""

def run_interactive_analyze():
    """Interactive CLI prompts to run single APK analysis."""
    try:
        print(f"\n{CYAN}--- SINGLE APK ANALYSIS CONFIGURATION ---{RESET}")
        
        # APK Path
        default_apk = "samples/vulnerable.apk"
        apk_path = input(f"Target APK path (default: {default_apk}): ").strip()
        if not apk_path:
            apk_path = default_apk
        if not os.path.exists(apk_path):
            print(f"{RED}[!] Error: Target APK path does not exist: {apk_path}{RESET}")
            return

        # Dynamic Directory
        default_dyn = "runtime_data/"
        dynamic_dir_input = input(f"Dynamic logs folder path (default: {default_dyn}, type 'none' to skip): ").strip()
        if dynamic_dir_input == "":
            dynamic_dir = default_dyn
        elif dynamic_dir_input.lower() == "none":
            dynamic_dir = ""
        else:
            dynamic_dir = dynamic_dir_input
            
        if dynamic_dir and not os.path.exists(dynamic_dir):
            print(f"{YELLOW}[!] Warning: Dynamic folder '{dynamic_dir}' does not exist. Dynamic checks will be skipped.{RESET}")

        # Output Folder
        default_out = "reports"
        output_dir = input(f"Output folder path (default: {default_out}): ").strip()
        if not output_dir:
            output_dir = default_out

        print(f"\n{YELLOW}[*] Launching analysis pipeline...{RESET}")
        logger = setup_logger(verbose=False)
        report_data = analyze_single_apk(apk_path, dynamic_dir, logger)
        
        # Save output reports
        os.makedirs(output_dir, exist_ok=True)
        json_path = os.path.join(output_dir, "final_risk_report.json")
        html_path = os.path.join(output_dir, "report.html")
        pdf_path = os.path.join(output_dir, "report.pdf")
        
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        generate_html_report(report_data, os.path.basename(apk_path), html_path)
        generate_pdf_report(report_data, os.path.basename(apk_path), pdf_path)
        
        print(f"\n{GREEN}[+] Security scan finished successfully!{RESET}")
        print(f"JSON findings:  {json_path}")
        print(f"HTML dashboard: {html_path}")
        print(f"PDF assessment: {pdf_path}")
        
        # Add history entry
        save_history_log(os.path.basename(apk_path), report_data.get("overall_risk", "INFO"), report_data.get("overall_risk_score", 0.0))
        
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Operation cancelled. Returning to main menu...{RESET}")
    except Exception as e:
        print(f"\n{RED}[!] Analysis failed: {e}{RESET}")

def run_interactive_compare():
    """Interactive CLI prompts to run comparison posture check."""
    try:
        print(f"\n{CYAN}--- APK POSTURE COMPARISON CONFIGURATION ---{RESET}")
        
        # Base APK
        default_old = "samples/vulnerable.apk"
        old_apk = input(f"Older baseline APK path (default: {default_old}): ").strip()
        if not old_apk:
            old_apk = default_old
        if not os.path.exists(old_apk):
            print(f"{RED}[!] Error: Baseline APK path does not exist: {old_apk}{RESET}")
            return

        # Target APK
        default_new = "samples/InsecureBankv2.apk"
        new_apk = input(f"Newer upgraded APK path (default: {default_new}): ").strip()
        if not new_apk:
            new_apk = default_new
        if not os.path.exists(new_apk):
            print(f"{RED}[!] Error: Upgraded APK path does not exist: {new_apk}{RESET}")
            return

        # Dynamic Directory
        default_dyn = "runtime_data/"
        dynamic_dir_input = input(f"Dynamic logs folder path (default: {default_dyn}, type 'none' to skip): ").strip()
        if dynamic_dir_input == "":
            dynamic_dir = default_dyn
        elif dynamic_dir_input.lower() == "none":
            dynamic_dir = ""
        else:
            dynamic_dir = dynamic_dir_input

        # Output Folder
        default_out = "reports"
        output_dir = input(f"Output folder path (default: {default_out}): ").strip()
        if not output_dir:
            output_dir = default_out

        print(f"\n{YELLOW}[*] Running double-scan delta analysis...{RESET}")
        logger = setup_logger(verbose=False)
        old_report = analyze_single_apk(old_apk, dynamic_dir, logger)
        new_report = analyze_single_apk(new_apk, dynamic_dir, logger)
        
        comparison_results = compare_reports(old_report, new_report)
        
        os.makedirs(output_dir, exist_ok=True)
        comparison_json_path = os.path.join(output_dir, "comparison_report.json")
        with open(comparison_json_path, "w", encoding="utf-8") as f:
            json.dump(comparison_results, f, indent=2)
            
        print(f"\n{GREEN}================ COMPARISON RESULTS DELTA ================{RESET}")
        print(f"Old Risk Score: {comparison_results['old_apk_risk_score']}/100")
        print(f"New Risk Score: {comparison_results['new_apk_risk_score']}/100")
        print(f"Difference    : {comparison_results['risk_difference']} points")
        print(f"Improvement   : {comparison_results['risk_improvement_percentage']}%")
        print(f"Summary       : {comparison_results['comparison_summary']}")
        print(f"{GREEN}=========================================================={RESET}")
        
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Operation cancelled. Returning to main menu...{RESET}")
    except Exception as e:
        print(f"\n{RED}[!] Comparison failed: {e}{RESET}")

def save_history_log(apk_name: str, risk: str, score: float):
    history_dir = "reports"
    os.makedirs(history_dir, exist_ok=True)
    history_path = os.path.join(history_dir, "history.json")
    scans = []
    if os.path.exists(history_path):
        try:
            with open(history_path, "r", encoding="utf-8") as f:
                scans = json.load(f)
        except:
            pass
            
    try:
        import datetime
        date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    except:
        date_str = time.strftime("%Y-%m-%d %H:%M:%S")
        
    scans.append({
        "apk_name": apk_name,
        "date": date_str,
        "risk": risk,
        "score": score,
        "status": "SUCCESS"
    })
    scans = scans[-50:]
    try:
        with open(history_path, "w", encoding="utf-8") as f:
            json.dump(scans, f, indent=2)
    except:
        pass

def show_interactive_menu():
    """Renders main interactive selection menu."""
    rules_cnt = 28
    rules_path = "rules.json"
    if os.path.exists(rules_path):
        try:
            with open(rules_path, "r", encoding="utf-8") as f:
                rules_cnt = len(json.load(f))
        except:
            pass

    while True:
        print(BANNER)
        print(f"{CYAN}Intelligence rules loaded : {rules_cnt}{RESET}")
        print(f"{CYAN}OWASP Top 10 Mapping      : Enabled{RESET}")
        print("-" * 50)
        print(f"{GREEN}1.{RESET} Analyze APK")
        print(f"{GREEN}2.{RESET} Compare APKs")
        print(f"{GREEN}3.{RESET} Launch GUI")
        print(f"{GREEN}4.{RESET} View Reports")
        print(f"{GREEN}5.{RESET} Open Reports Folder")
        print(f"{GREEN}6.{RESET} Settings")
        print(f"{GREEN}7.{RESET} Help Center")
        print(f"{GREEN}8.{RESET} About ACLDS")
        print(f"{GREEN}0.{RESET} Exit")
        print("-" * 50)
        
        try:
            choice = input(f"{YELLOW}Enter choice (0-8): {RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{RED}Exiting system...{RESET}")
            break
            
        if choice == "0" or not choice:
            print(f"{RED}Exiting system...{RESET}")
            break
        elif choice == "1":
            run_interactive_analyze()
        elif choice == "2":
            run_interactive_compare()
        elif choice == "3":
            launch_gui_app()
        elif choice == "4":
            view_interactive_reports()
        elif choice == "5":
            open_reports_folder_shell()
        elif choice == "6":
            configure_interactive_settings()
        elif choice == "7":
            sys.argv = [sys.argv[0], "--help"]
            main()
            sys.argv = [sys.argv[0]]
        elif choice == "8":
            print_about_details()
        else:
            print(f"{RED}[!] Invalid choice. Please select again.{RESET}")

def main():
    # Legacy compatibility patch mapping: python main.py <apk> <dir> -> aclds analyze <apk> <dir>
    if len(sys.argv) == 3 and not sys.argv[1].startswith("-") and not sys.argv[2].startswith("-"):
        sys.argv = [sys.argv[0], "analyze", sys.argv[1], sys.argv[2]]

    # Interactive Menu check
    if len(sys.argv) == 1:
        show_interactive_menu()
        return

    # Setup CLI Subcommand Parsers with clean automatic formatting
    parser = argparse.ArgumentParser(
        description="Android Credential Leakage Detection System V2 - CLI Tool",
        epilog="""
Examples:
  aclds
  aclds analyze samples/app.apk
  aclds analyze samples/app.apk --dynamic runtime_data/
  aclds compare old.apk new.apk --dynamic runtime_data/
  aclds gui
  aclds history
  aclds reports
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    # Register centralized version flag directly in argparse
    parser.add_argument("-v", "--version", action="version", version=f"Android Credential Leakage Detection System\nVersion {VERSION}")
    
    subparsers = parser.add_subparsers(dest="command", help="Subcommands")
    
    # Subcommand: analyze
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Decompile and analyze a single APK file",
        description="Decompiles target APK, extracts code assets, runs vulnerability check, parses logs if supplied, and outputs correlation reports."
    )
    analyze_parser.add_argument("apk_path", help="Path to target APK file")
    analyze_parser.add_argument("runtime_dir", nargs="?", default=None, help="Directory containing runtime logcat/network captures (Legacy positional)")
    analyze_parser.add_argument("--dynamic", help="Directory containing runtime traces")
    analyze_parser.add_argument("--output", help="Directory to save report outputs")
    analyze_parser.add_argument("--json", help="Custom output path for JSON report")
    analyze_parser.add_argument("--html", help="Custom output path for HTML report")
    analyze_parser.add_argument("--pdf", help="Custom output path for PDF report")
    analyze_parser.add_argument("--verbose", action="store_true", help="Enable verbose debug logs")
    
    # Subcommand: compare
    compare_parser = subparsers.add_parser(
        "compare",
        help="Diff and compare security posture between two APKs",
        description="Runs scans on old and new builds, computing risk delta score, patched removals, and added vulnerabilities."
    )
    compare_parser.add_argument("old_apk", help="Path to older baseline APK file")
    compare_parser.add_argument("new_apk", help="Path to newer patched APK file")
    compare_parser.add_argument("--dynamic", help="Directory containing runtime log files")
    compare_parser.add_argument("--output", help="Directory to save report outputs")
    compare_parser.add_argument("--verbose", action="store_true", help="Enable verbose debug logs")
    
    # Subcommand: gui
    gui_parser = subparsers.add_parser(
        "gui",
        help="Launch the PySide6 Desktop GUI application",
        description="Launches the professional cybersecurity dashboard GUI built with PySide6.",
        epilog="Example: aclds gui"
    )
    
    # Subcommand: reports
    reports_parser = subparsers.add_parser(
        "reports",
        help="List and open generated JSON/HTML/PDF report files",
        description="Launches the interactive CLI wizard to browse and open compiled JSON, HTML, and PDF reports.",
        epilog="Example: aclds reports"
    )
    
    # Subcommand: history
    history_parser = subparsers.add_parser(
        "history",
        help="Show chronological scan runs logs in terminal",
        description="Prints a tabular log of the last 20 APK scans with dates, overall risk ratings, and scores.",
        epilog="Example: aclds history"
    )
    
    # Subcommand: version
    subparsers.add_parser(
        "version",
        help="Show application version details",
        description="Prints version information for ACLDS."
    )

    # Run argparse parser
    args = parser.parse_args()

    # Subcommand handlers
    if args.command == "version":
        print(f"Android Credential Leakage Detection System\nVersion {VERSION}")
        return
        
    elif args.command == "gui":
        launch_gui_app()
        
    elif args.command == "reports":
        view_interactive_reports()
        
    elif args.command == "history":
        show_scan_history_cli()
        
    elif args.command == "compare":
        logger = setup_logger(verbose=args.verbose)
        try:
            old_report = analyze_single_apk(args.old_apk, args.dynamic, logger)
            new_report = analyze_single_apk(args.new_apk, args.dynamic, logger)
            
            comparison_results = compare_reports(old_report, new_report)
            
            output_dir = args.output if args.output else "reports"
            os.makedirs(output_dir, exist_ok=True)
            comparison_json_path = os.path.join(output_dir, "comparison_report.json")
            
            with open(comparison_json_path, "w", encoding="utf-8") as f:
                json.dump(comparison_results, f, indent=2)
                
            logger.info(f"Comparison report saved to {comparison_json_path}")
            
            print("\n================ APK COMPARISON SUMMARY ================")
            print(f"Old APK Risk Score: {comparison_results['old_apk_risk_score']}/100")
            print(f"New APK Risk Score: {comparison_results['new_apk_risk_score']}/100")
            print(f"Risk Score Difference: {comparison_results['risk_difference']} points")
            print(f"Risk Improvement: {comparison_results['risk_improvement_percentage']}%")
            print(f"Removed Vulnerabilities: {len(comparison_results['removed_vulnerabilities'])}")
            print(f"New Vulnerabilities: {len(comparison_results['new_vulnerabilities'])}")
            print(f"Summary: {comparison_results['comparison_summary']}")
            print("========================================================")
        except Exception as e:
            logger.error(f"Comparison scan failed: {e}", exc_info=args.verbose)
            sys.exit(1)
            
    elif args.command == "analyze":
        logger = setup_logger(verbose=args.verbose)
        apk_path = args.apk_path
        dynamic_dir = args.dynamic if args.dynamic else args.runtime_dir
        
        if not os.path.exists(apk_path):
            logger.error(f"Target APK path does not exist: {apk_path}")
            sys.exit(1)
            
        try:
            report_data = analyze_single_apk(apk_path, dynamic_dir, logger)
            
            output_dir = args.output if args.output else "reports"
            os.makedirs(output_dir, exist_ok=True)
            
            json_path = args.json if args.json else os.path.join(output_dir, "final_risk_report.json")
            html_path = args.html if args.html else os.path.join(output_dir, "report.html")
            pdf_path = args.pdf if args.pdf else os.path.join(output_dir, "report.pdf")
            
            # Save files
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2)
            generate_html_report(report_data, os.path.basename(apk_path), html_path)
            generate_pdf_report(report_data, os.path.basename(apk_path), pdf_path)
            
            logger.info("Assessment reports successfully compiled.")
            save_history_log(os.path.basename(apk_path), report_data.get("overall_risk", "INFO"), report_data.get("overall_risk_score", 0.0))
            
            # Print legacy output tables
            summary_table = [
                ["Overall Risk", report_data.get("overall_risk")],
                ["Overall Risk Score (V2)", report_data.get("overall_risk_score")],
                ["Static Findings", report_data.get("static_findings_count")],
                ["Dynamic Log Findings", report_data.get("dynamic_logcat_findings_count")],
                ["Dynamic Network Findings", report_data.get("dynamic_network_findings_count")]
            ]
            print("\n================ APK SECURITY REPORT ================")
            print(tabulate(summary_table, headers=["Metric", "Value"], tablefmt="grid"))
            
            if "category_summary" in report_data:
                print("\n================ FINDING SUMMARY ================")
                category_table = []
                for category, count in report_data["category_summary"].items():
                    category_table.append([category, count])
                print(tabulate(category_table, headers=["Category", "Count"], tablefmt="fancy_grid"))
                
        except Exception as e:
            logger.error(f"Analysis scan failed: {e}", exc_info=args.verbose)
            sys.exit(1)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
