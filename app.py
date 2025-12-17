import sys
import logging
import os

# Configure Logging first
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("projectx.log", mode='w'),
        logging.StreamHandler(sys.stdout)
    ]
)

from PyQt6.QtWidgets import QApplication, QSplashScreen, QProgressBar, QLabel, QVBoxLayout, QWidget
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QPixmap, QColor, QFont
from main_window import MainWindow
from workers import ScanWorker

class LoaderScreen(QSplashScreen):
    def __init__(self):
        super().__init__()
        self.setFixedSize(500, 350)
        self.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        
        # Main Container with rounded corners
        self.layout_container = QWidget(self)
        self.layout_container.setGeometry(0, 0, 500, 350)
        self.layout_container.setStyleSheet("""
            QWidget {
                background-color: #1e1e1e;
                border: 2px solid #333;
                border-radius: 15px;
            }
        """)
        
        layout = QVBoxLayout(self.layout_container)
        layout.setContentsMargins(30, 40, 30, 40)
        layout.setSpacing(15)
        
        # Icon
        lbl_icon = QLabel("🛡️")
        lbl_icon.setStyleSheet("font-size: 64px; border: none; background: transparent;")
        lbl_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(lbl_icon)
        
        # Title
        title = QLabel("ProjectX Security")
        title.setStyleSheet("color: #007acc; font-size: 28px; font-weight: bold; border: none; background: transparent;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Description
        desc = QLabel("Advanced Endpoint Protection & Vulnerability Scanner\nInitializing system inventory, network interception, and threat feeds...")
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #888888; font-size: 13px; font-style: italic; border: none; background: transparent;")
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(desc)
        
        layout.addStretch()
        
        # Current Action / Buffer
        self.status = QLabel("Preparing enviroment...")
        self.status.setStyleSheet("color: #ffffff; font-size: 14px; font-weight: bold; border: none; background: transparent;")
        self.status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status)
        
        # Progress Bar
        self.progress = QProgressBar()
        self.progress.setStyleSheet("""
            QProgressBar {
                border: none;
                background-color: #2d2d2d;
                height: 8px;
                border-radius: 4px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 #007acc, stop:1 #00b4d8);
                border-radius: 4px;
            }
        """)
        self.progress.setRange(0, 0) # Indeterminate "Pulse"
        layout.addWidget(self.progress)

        self.center_on_screen()

    def center_on_screen(self):
        screen = QApplication.primaryScreen().availableGeometry()
        size = self.geometry()
        self.move(int((screen.width() - size.width()) / 2), 
                  int((screen.height() - size.height()) / 2))

    def update_status(self, msg):
        self.status.setText(msg)

if __name__ == "__main__":
    logging.info("Starting ProjectX Desktop...")
    
    app = QApplication(sys.argv)
    app.setApplicationName("ProjectX")
    
    # Show Loader
    loader = LoaderScreen()
    loader.show()
    
    # Check Safe Mode
    from managers import ConfigManager
    config = ConfigManager.load_config()
    safe_mode = config.get("safe_mode", "false").lower() == "true"
    
    if safe_mode:
        logging.info("Safe Mode (Fast Load) Enabled. Skipping initial scan.")
        loader.update_status("Fast Load: Retrieving cached data...")
        
        # Direct Launch with slight delay for visual confirmation
        def fast_launch():
            logging.info("Fast Launching Dashboard.")
            global window
            window = MainWindow()
            window.show()
            loader.close()
            
        # Use a timer to simulate 'Retrieving cached data' briefly (e.g., 800ms)
        QTimer.singleShot(800, fast_launch)
        
    else:
        logging.info("Full Mode. Starting initial scan...")
        # Worker for initial scan
        worker = ScanWorker(skip_cve_sync=True)
        worker.progress.connect(loader.update_status)
        
        def on_scan_finished():
            logging.info("Initial Scan Complete. Launching Dashboard.")
            # Create Main Window, it will load fresh data from DB
            global window
            window = MainWindow()
            window.show()
            loader.close()
            
        worker.finished.connect(on_scan_finished)
        worker.start()
    
    exit_code = app.exec()
    
    # Explicit Cleanup
    root_logger = logging.getLogger()
    for h in root_logger.handlers[:]:
        if "QtLogHandler" in str(type(h)):
            root_logger.removeHandler(h)
    
    sys.exit(exit_code)
