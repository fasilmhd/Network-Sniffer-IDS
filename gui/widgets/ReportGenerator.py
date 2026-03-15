# gui/widgets/ReportGenerator.py
import csv
from datetime import datetime
from PySide6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox, QFileDialog, QMessageBox
from PySide6.QtPrintSupport import QPrinter
from PySide6.QtGui import QTextDocument

class ReportGeneratorDialog(QDialog):
    def __init__(self, dashboard_panel, parent=None):
        super().__init__(parent)
        self.dashboard = dashboard_panel
        self.setWindowTitle("Generate Security Report")
        self.setModal(True)
        self.resize(350, 150)

        layout = QVBoxLayout(self)
        
        layout.addWidget(QLabel("Select Report Format:"))
        self.fmt = QComboBox()
        self.fmt.addItems(["PDF Document", "CSV Export"])
        layout.addWidget(self.fmt)
        
        btns = QHBoxLayout()
        btns.addStretch()
        gen_btn = QPushButton("Generate Report")
        gen_btn.clicked.connect(self._generate)
        btns.addWidget(gen_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btns.addWidget(cancel_btn)
        
        layout.addLayout(btns)

    def _generate(self):
        fmt = self.fmt.currentText()
        if fmt == "CSV Export":
            fn, _ = QFileDialog.getSaveFileName(self, "Save Report", "security_report.csv", "CSV Files (*.csv)")
            if fn:
                self._export_csv(fn)
                self.accept()
        else:
            fn, _ = QFileDialog.getSaveFileName(self, "Save Report", "security_report.pdf", "PDF Files (*.pdf)")
            if fn:
                self._export_pdf(fn)
                self.accept()

    def _get_stats(self):
        db = self.dashboard
        attacks = db._attack_counts
        total = db._total_attacks
        pkts = db._pkt_count
        level = db._threat_lbl.text()
        top_ips = db._attacker_ips.most_common(5)
        blocked_ips = db._blocked_ips
        return attacks, total, pkts, level, top_ips, blocked_ips

    def _export_csv(self, filename: str):
        attacks, total, pkts, level, top_ips, blocked_ips = self._get_stats()
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Network Security Report", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
                writer.writerow(["Threat Level", level])
                writer.writerow(["Total Attacks Detected", total])
                writer.writerow([])
                writer.writerow(["Attack Type", "Count"])
                for k, v in attacks.items():
                    writer.writerow([k, v])
                writer.writerow([])
                writer.writerow(["Top Attacker IP", "Hits"])
                for ip, count in top_ips:
                    writer.writerow([ip, count])
                writer.writerow([])
                writer.writerow(["Blocked IPs"])
                for ip in blocked_ips:
                    writer.writerow([ip])
            QMessageBox.information(self, "Success", f"CSV Report saved to {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save CSV: {e}")

    def _export_pdf(self, filename: str):
        attacks, total, pkts, level, top_ips, blocked_ips = self._get_stats()
        
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; color: #333; }}
                h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 5px; }}
                h2 {{ color: #2980b9; margin-top: 20px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; color: #333; font-weight: bold; }}
                .level {{ font-size: 18px; font-weight: bold; padding: 10px; background-color: #ecf0f1; border-radius: 5px; display: inline-block; }}
            </style>
        </head>
        <body>
            <h1>Network Security Report</h1>
            <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <div class="level">Current Threat Level: {level}</div>
            <p><strong>Total Attacks Detected:</strong> {total}</p>
            
            <h2>Attack Statistics</h2>
            <table>
                <tr><th>Attack Type</th><th>Occurrences</th></tr>
        """
        for k, v in attacks.items():
            html += f"<tr><td>{k}</td><td>{v}</td></tr>"
            
        html += """
            </table>
            <h2>Top Attacker IPs</h2>
            <table>
                <tr><th>IP Address</th><th>Hits</th></tr>
        """
        for ip, count in top_ips:
            html += f"<tr><td>{ip}</td><td>{count}</td></tr>"
            
        if blocked_ips:
            html += "</table><h2>Blocked IPs (Firewall)</h2><ul>"
            for ip in blocked_ips:
                html += f"<li>{ip}</li>"
            html += "</ul>"
            
        html += "</body></html>"
        
        try:
            doc = QTextDocument()
            doc.setHtml(html)
            printer = QPrinter()
            printer.setOutputFormat(QPrinter.PdfFormat)
            printer.setOutputFileName(filename)
            doc.print_(printer)
            QMessageBox.information(self, "Success", f"PDF Report saved to {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save PDF: {e}")
