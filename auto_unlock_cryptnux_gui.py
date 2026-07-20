#!/usr/bin/env python3
"""
AutoUnlockCryptnux GUI - Interface graphique pour la gestion LUKS via TPM2
"""

import sys
import os
import json
from pathlib import Path

# PyQt5 peut être dans les dist-packages système (Python 3.12+)
if 'PyQt5' not in sys.modules:
    _sys_dist = '/usr/lib/python3/dist-packages'
    if _sys_dist not in sys.path:
        sys.path.insert(0, _sys_dist)

# Xcursor.size=64 (Xresources) donne un curseur géant dans Qt — on force la taille GNOME
if 'XCURSOR_SIZE' not in os.environ:
    os.environ['XCURSOR_SIZE'] = '24'

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTableWidget, QTableWidgetItem, QMessageBox,
    QDialog, QDialogButtonBox, QGroupBox, QLineEdit, QComboBox,
    QTextEdit, QProgressBar, QSplitter, QFrame, QHeaderView
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor

import auto_unlock_cryptnux as tpm2


# ---------------------------------------------------------------------------
# Worker thread
# ---------------------------------------------------------------------------

class Worker(QThread):
    success = pyqtSignal(str)
    failure = pyqtSignal(str)
    log_msg = pyqtSignal(str)

    def __init__(self, task, **kwargs):
        super().__init__()
        self.task = task
        self.kwargs = kwargs

    def run(self):
        try:
            if self.task == 'list':
                devices = tpm2.get_luks_devices()
                for dev in devices:
                    if dev['status'] == 'fermé':
                        bound, info = tpm2.get_tpm2_binding_status(dev['device'])
                        dev['tpm2_bound'] = bound
                        dev['tpm2_info'] = info
                self.success.emit(json.dumps(devices))

            elif self.task == 'bind':
                ok, msg = tpm2.bind_luks_to_tpm2(
                    self.kwargs['device'], self.kwargs['pcr']
                )
                if ok:
                    self.success.emit(msg)
                else:
                    self.failure.emit(msg)

            elif self.task == 'unbind':
                ok, msg = tpm2.unbind_luks_from_tpm2(self.kwargs['device'])
                if ok:
                    self.success.emit(msg)
                else:
                    self.failure.emit(msg)

            elif self.task == 'status':
                available, dev = tpm2.check_tpm2_available()
                backend = tpm2.get_tpm2_backend()
                pcr = tpm2.get_pcr_values() if available else '(TPM2 non disponible)'
                info = {
                    'available': available,
                    'device': dev,
                    'backend': backend,
                    'pcr': pcr,
                }
                self.success.emit(json.dumps(info))

        except Exception as e:
            self.failure.emit(str(e))


# ---------------------------------------------------------------------------
# Dialogue de liaison TPM2
# ---------------------------------------------------------------------------

class BindDialog(QDialog):
    def __init__(self, devices, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Lier une partition au TPM2")
        self.setMinimumWidth(420)
        self._build_ui(devices)

    def _build_ui(self, devices):
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Partition LUKS :"))
        self.combo = QComboBox()
        for dev in devices:
            if dev['status'] == 'fermé':
                self.combo.addItem(f"{dev['device']}  ({dev['size']})", dev['device'])
        layout.addWidget(self.combo)

        layout.addWidget(QLabel("PCR IDs (ex: 7  ou  0,1,7) :"))
        self.pcr_edit = QLineEdit("0+2+4+7")
        self.pcr_edit.setPlaceholderText("0+2+4+7")
        layout.addWidget(self.pcr_edit)

        note = QLabel(
            "PCR 0+2+4+7 = configuration recommandée pour le workflow centralisé\n"
            "Vous pouvez également saisir une liste comme 0,1,7"
        )
        note.setStyleSheet("color: gray; font-size: 11px;")
        layout.addWidget(note)

        layout.addSpacing(8)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_device(self):
        return self.combo.currentData()

    def get_pcr(self):
        return self.pcr_edit.text().strip() or '0+2+4+7'


# ---------------------------------------------------------------------------
# Fenêtre principale
# ---------------------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AutoUnlockCryptnux — Déverrouillage LUKS via TPM2")
        self.setMinimumSize(860, 600)
        self._devices = []
        self._build_ui()
        self._refresh()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setSpacing(8)

        # Titre
        title = QLabel("Gestionnaire LUKS / TPM2")
        title.setFont(QFont("Sans-serif", 15, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        root.addWidget(title)

        # Barre d'outils
        toolbar = QGroupBox("Actions")
        tb_layout = QHBoxLayout()
        self.btn_refresh = QPushButton("Actualiser")
        self.btn_refresh.clicked.connect(self._refresh)
        self.btn_bind = QPushButton("Lier au TPM2")
        self.btn_bind.clicked.connect(self._bind)
        self.btn_unbind = QPushButton("Supprimer liaison")
        self.btn_unbind.clicked.connect(self._unbind)
        self.btn_status = QPushButton("Statut TPM2")
        self.btn_status.clicked.connect(self._show_status)
        for btn in (self.btn_refresh, self.btn_bind, self.btn_unbind, self.btn_status):
            tb_layout.addWidget(btn)
        tb_layout.addStretch()
        toolbar.setLayout(tb_layout)
        root.addWidget(toolbar)

        # Tableau des partitions
        part_group = QGroupBox("Partitions LUKS")
        part_layout = QVBoxLayout()
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Périphérique", "Taille", "Statut", "TPM2"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        part_layout.addWidget(self.table)
        part_group.setLayout(part_layout)
        root.addWidget(part_group)

        # Journal
        log_group = QGroupBox("Journal")
        log_layout = QVBoxLayout()
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(140)
        self.log.setFont(QFont("Monospace", 9))
        log_layout.addWidget(self.log)
        log_group.setLayout(log_layout)
        root.addWidget(log_group)

        # Progression
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setVisible(False)
        root.addWidget(self.progress)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _log(self, msg):
        self.log.append(msg)

    def _set_busy(self, busy):
        self.progress.setVisible(busy)
        for btn in (self.btn_refresh, self.btn_bind, self.btn_unbind, self.btn_status):
            btn.setEnabled(not busy)

    def _selected_device(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Sélection", "Sélectionnez d'abord une partition.")
            return None
        return self.table.item(row, 0).text()

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def _refresh(self):
        self._log("Actualisation de la liste des partitions...")
        self._set_busy(True)
        self.worker = Worker('list')
        self.worker.success.connect(self._on_list_loaded)
        self.worker.failure.connect(self._on_error)
        self.worker.finished.connect(lambda: self._set_busy(False))
        self.worker.start()

    def _on_list_loaded(self, payload):
        self._devices = json.loads(payload)
        self.table.setRowCount(len(self._devices))
        for i, dev in enumerate(self._devices):
            self.table.setItem(i, 0, QTableWidgetItem(dev['device']))
            self.table.setItem(i, 1, QTableWidgetItem(dev.get('size', '')))
            self.table.setItem(i, 2, QTableWidgetItem(dev['status']))
            if dev['status'] == 'fermé':
                bound = dev.get('tpm2_bound', False)
                item = QTableWidgetItem("Lié" if bound else "Non lié")
                item.setForeground(QColor('green') if bound else QColor('gray'))
                self.table.setItem(i, 3, item)
            else:
                self.table.setItem(i, 3, QTableWidgetItem("—"))
        self._log(f"{len(self._devices)} partition(s) détectée(s).")

    def _bind(self):
        closed = [d for d in self._devices if d['status'] == 'fermé']
        if not closed:
            QMessageBox.information(self, "Info", "Aucune partition LUKS fermée disponible.")
            return
        dlg = BindDialog(closed, self)
        if dlg.exec_() != QDialog.Accepted:
            return
        device = dlg.get_device()
        pcr = dlg.get_pcr()
        if not device:
            return
        self._log(f"Liaison TPM2 pour {device} (PCR: {pcr})…")
        self._set_busy(True)
        self.worker = Worker('bind', device=device, pcr=pcr)
        self.worker.success.connect(lambda m: (self._log(f"OK : {m}"), self._refresh()))
        self.worker.failure.connect(self._on_error)
        self.worker.log_msg.connect(self._log)
        self.worker.finished.connect(lambda: self._set_busy(False))
        self.worker.start()

    def _unbind(self):
        device = self._selected_device()
        if not device:
            return
        reply = QMessageBox.question(
            self, "Confirmation",
            f"Supprimer la liaison TPM2 pour {device} ?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return
        self._log(f"Suppression liaison TPM2 pour {device}…")
        self._set_busy(True)
        self.worker = Worker('unbind', device=device)
        self.worker.success.connect(lambda m: (self._log(f"OK : {m}"), self._refresh()))
        self.worker.failure.connect(self._on_error)
        self.worker.finished.connect(lambda: self._set_busy(False))
        self.worker.start()

    def _show_status(self):
        self._log("Lecture du statut TPM2…")
        self._set_busy(True)
        self.worker = Worker('status')
        self.worker.success.connect(self._on_status)
        self.worker.failure.connect(self._on_error)
        self.worker.finished.connect(lambda: self._set_busy(False))
        self.worker.start()

    def _on_status(self, payload):
        info = json.loads(payload)
        lines = [
            f"TPM2 hardware : {'Oui (' + info['device'] + ')' if info['available'] else 'Non détecté'}",
            f"Backend       : {info['backend'] or 'Aucun'}",
            "",
            "Valeurs PCR sha256 :",
            info['pcr'],
        ]
        QMessageBox.information(self, "Statut TPM2", '\n'.join(lines))

    def _on_error(self, msg):
        self._log(f"ERREUR : {msg}")
        QMessageBox.critical(self, "Erreur", msg)


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

def main():
    if os.geteuid() != 0:
        print("Attention : certaines opérations nécessitent les droits root.")

    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
