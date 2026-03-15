from PySide6.QtWidgets import QWidget, QVBoxLayout, QPushButton
from PySide6.QtCore import QTimer
import psutil, pyqtgraph as pg

class MonitorPanel(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        self.cpu_plot = pg.PlotWidget(title="CPU %")
        self.cpu_curve = self.cpu_plot.plot(pen='y')
        layout.addWidget(self.cpu_plot)

        self.ram_plot = pg.PlotWidget(title="RAM %")
        self.ram_curve = self.ram_plot.plot(pen='r')
        layout.addWidget(self.ram_plot)

        btn = QPushButton("Start Monitoring")
        btn.clicked.connect(self._toggle)
        layout.addWidget(btn)

        self.timer = QTimer()
        self.timer.timeout.connect(self._update)
        self.data_cpu = []
        self.data_ram = []

    def _toggle(self):
        if self.timer.isActive():
            self.timer.stop()
        else:
            self.timer.start(1000)

    def _update(self):
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        self.data_cpu.append(cpu)
        self.data_ram.append(ram)
        if len(self.data_cpu) > 60:
            self.data_cpu.pop(0)
            self.data_ram.pop(0)
        self.cpu_curve.setData(self.data_cpu)
        self.ram_curve.setData(self.data_ram)