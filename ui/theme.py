# Theme and stylesheet definitions for Android Credential Leakage Detector V2

# Cyberpunk / Dark Theme colors
DARK_THEME = """
QMainWindow {
    background-color: #0f172a;
}
QWidget {
    font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    font-size: 13px;
    color: #f8fafc;
}
QFrame#Sidebar {
    background-color: #1e293b;
    border-right: 1px solid #334155;
}
QPushButton#SidebarBtn {
    background-color: transparent;
    color: #94a3b8;
    border: none;
    border-radius: 6px;
    padding: 12px 20px;
    text-align: left;
    font-weight: bold;
    font-size: 14px;
}
QPushButton#SidebarBtn:hover {
    background-color: #334155;
    color: #10b981;
}
QPushButton#SidebarBtn:checked {
    background-color: #10b981;
    color: #0f172a;
}
QFrame#Card {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 10px;
}
QLabel#CardTitle {
    font-size: 16px;
    font-weight: bold;
    color: #10b981;
    border-bottom: 1px solid #334155;
    padding-bottom: 8px;
}
QLineEdit, QComboBox {
    background-color: #0f172a;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 8px;
    color: #f8fafc;
}
QLineEdit:focus, QComboBox:focus {
    border: 1px solid #10b981;
}
QPushButton#PrimaryBtn {
    background-color: #10b981;
    color: #0f172a;
    font-weight: bold;
    border: none;
    border-radius: 6px;
    padding: 10px 20px;
    font-size: 14px;
}
QPushButton#PrimaryBtn:hover {
    background-color: #34d399;
}
QPushButton#SecondaryBtn {
    background-color: #334155;
    color: #f8fafc;
    border: 1px solid #475569;
    border-radius: 6px;
    padding: 8px 16px;
}
QPushButton#SecondaryBtn:hover {
    background-color: #475569;
}
QProgressBar {
    background-color: #334155;
    border: none;
    border-radius: 8px;
    text-align: center;
    color: white;
    font-weight: bold;
}
QProgressBar::chunk {
    background-color: #10b981;
    border-radius: 8px;
}
QTextEdit#Console {
    background-color: #020617;
    color: #38bdf8;
    border: 1px solid #334155;
    font-family: Consolas, Monaco, monospace;
    font-size: 12px;
    border-radius: 8px;
}
QScrollBar:vertical {
    border: none;
    background-color: #0f172a;
    width: 10px;
}
QScrollBar::handle:vertical {
    background-color: #475569;
    border-radius: 5px;
    min-height: 20px;
}
QScrollBar::handle:vertical:hover {
    background-color: #10b981;
}
"""

# Light Theme
LIGHT_THEME = """
QMainWindow {
    background-color: #f8fafc;
}
QWidget {
    font-family: "Segoe UI", Arial, sans-serif;
    font-size: 13px;
    color: #0f172a;
}
QFrame#Sidebar {
    background-color: #ffffff;
    border-right: 1px solid #e2e8f0;
}
QPushButton#SidebarBtn {
    background-color: transparent;
    color: #475569;
    border: none;
    border-radius: 6px;
    padding: 12px 20px;
    text-align: left;
    font-weight: bold;
    font-size: 14px;
}
QPushButton#SidebarBtn:hover {
    background-color: #f1f5f9;
    color: #10b981;
}
QPushButton#SidebarBtn:checked {
    background-color: #10b981;
    color: white;
}
QFrame#Card {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 10px;
}
QLabel#CardTitle {
    font-size: 16px;
    font-weight: bold;
    color: #10b981;
    border-bottom: 1px solid #f1f5f9;
    padding-bottom: 8px;
}
QLineEdit, QComboBox {
    background-color: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    padding: 8px;
    color: #0f172a;
}
QLineEdit:focus, QComboBox:focus {
    border: 1px solid #10b981;
}
QPushButton#PrimaryBtn {
    background-color: #10b981;
    color: white;
    font-weight: bold;
    border: none;
    border-radius: 6px;
    padding: 10px 20px;
    font-size: 14px;
}
QPushButton#PrimaryBtn:hover {
    background-color: #059669;
}
QPushButton#SecondaryBtn {
    background-color: #f1f5f9;
    color: #475569;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    padding: 8px 16px;
}
QPushButton#SecondaryBtn:hover {
    background-color: #e2e8f0;
}
QProgressBar {
    background-color: #e2e8f0;
    border: none;
    border-radius: 8px;
    text-align: center;
    color: #0f172a;
    font-weight: bold;
}
QProgressBar::chunk {
    background-color: #10b981;
    border-radius: 8px;
}
QTextEdit#Console {
    background-color: #ffffff;
    color: #0f172a;
    border: 1px solid #cbd5e1;
    font-family: monospace;
    font-size: 12px;
    border-radius: 8px;
}
"""

# Cyber Green (Matrix / Retro Terminal Theme)
CYBER_GREEN_THEME = """
QMainWindow {
    background-color: #000000;
}
QWidget {
    font-family: Consolas, Monaco, monospace;
    font-size: 13px;
    color: #00ff00;
}
QFrame#Sidebar {
    background-color: #0d1117;
    border-right: 2px solid #00ff00;
}
QPushButton#SidebarBtn {
    background-color: transparent;
    color: #00aa00;
    border: none;
    border-radius: 0px;
    padding: 12px 20px;
    text-align: left;
    font-weight: bold;
    font-size: 14px;
}
QPushButton#SidebarBtn:hover {
    background-color: #0d1117;
    color: #39ff14;
    border: 1px solid #39ff14;
}
QPushButton#SidebarBtn:checked {
    background-color: #00ff00;
    color: #000000;
}
QFrame#Card {
    background-color: #050505;
    border: 1px solid #00ff00;
    border-radius: 0px;
}
QLabel#CardTitle {
    font-size: 16px;
    font-weight: bold;
    color: #39ff14;
    border-bottom: 1px solid #00ff00;
    padding-bottom: 8px;
}
QLineEdit, QComboBox {
    background-color: #000000;
    border: 1px solid #00ff00;
    border-radius: 0px;
    padding: 8px;
    color: #00ff00;
}
QLineEdit:focus, QComboBox:focus {
    border: 2px solid #39ff14;
}
QPushButton#PrimaryBtn {
    background-color: #00ff00;
    color: #000000;
    font-weight: bold;
    border: 1px solid #39ff14;
    border-radius: 0px;
    padding: 10px 20px;
    font-size: 14px;
}
QPushButton#PrimaryBtn:hover {
    background-color: #003300;
    color: #39ff14;
}
QPushButton#SecondaryBtn {
    background-color: #000000;
    color: #00ff00;
    border: 1px solid #00ff00;
    border-radius: 0px;
    padding: 8px 16px;
}
QPushButton#SecondaryBtn:hover {
    background-color: #00aa00;
    color: #000000;
}
QProgressBar {
    background-color: #000000;
    border: 1px solid #00ff00;
    border-radius: 0px;
    text-align: center;
    color: #00ff00;
}
QProgressBar::chunk {
    background-color: #00ff00;
}
QTextEdit#Console {
    background-color: #000000;
    color: #39ff14;
    border: 1px solid #00ff00;
    font-family: monospace;
    font-size: 12px;
    border-radius: 0px;
}
"""

def get_stylesheet(theme_name: str) -> str:
    """Returns the stylesheet string corresponding to the theme name."""
    theme = theme_name.lower().replace(" ", "_")
    if theme == "light":
        return LIGHT_THEME
    elif theme == "cyber_green":
        return CYBER_GREEN_THEME
    return DARK_THEME
