import sys
import os
import hashlib
import pickle
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFileDialog, QComboBox, QMessageBox, QAbstractScrollArea, QTableWidget, QTableWidgetItem, QSizePolicy, QFrame, QProgressBar
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, QThread, pyqtSignal

BUTTON_FONT = QFont()
BUTTON_FONT.setPointSize(16)
BUTTON_FONT.setBold(True)
BUTTON_FONT.setFamily("Calibri")

SIMPLE_FONT = QFont()
SIMPLE_FONT.setPointSize(14)
SIMPLE_FONT.setBold(False)
SIMPLE_FONT.setFamily("Calibri")

class HashGenerator(QThread):
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal()

    def __init__(self, folder_path, algorithm):
        super().__init__()
        self.folder_path = folder_path
        self.algorithm = algorithm

        folder_name = os.path.basename(folder_path)
        self.hash_file_name = os.path.join("hashes", f"{folder_name}_{algorithm}.bin")

    def run(self):
        total_files = 0
        for root, _, files in os.walk(self.folder_path):
            total_files += len(files)

        current_progress = 0

        generated_hashes = {}
        not_accessed_files = []
        for root, _, files in os.walk(self.folder_path):
            for filename in files:
                file_path = os.path.join(root, filename).replace("/", "\\")
                try:
                    with open(file_path, "rb") as file:
                        file_contents = file.read()
                        hash_object = hashlib.new(self.algorithm)
                        hash_object.update(file_contents)
                        file_hash = hash_object.hexdigest()
                        generated_hashes[file_path] = file_hash
                except(PermissionError):
                    not_accessed_files.append(file_path)
                except:
                    not_accessed_files.append(file_path)

                current_progress += 1
                progress_percentage = int((current_progress / total_files) * 100)
                self.progress_signal.emit(progress_percentage)

        with open(self.hash_file_name, "wb") as file:
            pickle.dump(generated_hashes, file)
        self.finished_signal.emit()

class HashVerifier(QThread):
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal()

    def __init__(self, folder_path, algorithm, match_table, corrupt_table):
        super().__init__()
        self.folder_path = folder_path
        self.algorithm = algorithm
        self.match_table = match_table
        self.corrupt_table = corrupt_table

        folder_name = os.path.basename(folder_path)
        self.hash_file_name = os.path.join("hashes", f"{folder_name}_{algorithm}.bin")

    def run(self):
        total_files = 0
        for root, _, files in os.walk(self.folder_path):
            total_files += len(files)

        current_progress = 0

        with open(self.hash_file_name, "rb") as file:
            generated_hashes = pickle.load(file)

        status_dict = {"Match": [], "Corrupt": [], "Not Found": []}
        not_accessed_files = []
        for root, _, files in os.walk(self.folder_path):
            for filename in files:
                file_path = os.path.join(root, filename).replace("/", "\\")
                try:
                    with open(file_path, "rb") as file:
                        file_contents = file.read()
                        hash_object = hashlib.new(self.algorithm)
                        hash_object.update(file_contents)
                        file_hash = hash_object.hexdigest()
                        if file_path in generated_hashes:
                            if file_hash == generated_hashes[file_path]:
                                status_dict["Match"].append(file_path)
                            else:
                                status_dict["Corrupt"].append(file_path)
                        else:
                            status_dict["Not Found"].append(file_path)
                except(PermissionError):
                    not_accessed_files.append(file_path)
                except:
                    not_accessed_files.append(file_path)

                current_progress += 1
                progress_percentage = int((current_progress / total_files) * 100)
                self.progress_signal.emit(progress_percentage)

        match_string = f"Matched Files ({len(status_dict['Match'])})"
        corrput_string = f"Corrupt Files ({len(status_dict['Corrupt'])})"

        self.match_table.setRowCount(len(status_dict['Match']))  # Set the number of rows based on the length of the list
        self.match_table.setHorizontalHeaderLabels([match_string])

        # Populate the table with the list values
        for row, value in enumerate(status_dict['Match']):
            item = QTableWidgetItem(str(value))
            self.match_table.setItem(row, 0, item)

        self.corrupt_table.setRowCount(len(status_dict['Corrupt']))  # Set the number of rows based on the length of the list
        self.corrupt_table.setHorizontalHeaderLabels([corrput_string])

        # Populate the table with the list values
        for row, value in enumerate(status_dict['Corrupt']):
            item = QTableWidgetItem(str(value))
            self.corrupt_table.setItem(row, 0, item)
        self.finished_signal.emit()

class FileIntegrityCheckerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("HashApp")
        self.resize(1000, 600)

        self.folder_path = ""

        # Widgets
        self.hash_algorithms = ["md5", "sha1", "sha256", "sha512"]
        self.combo_box = QComboBox()
        self.combo_box.setFont(SIMPLE_FONT)
        self.combo_box.addItems(self.hash_algorithms)

        self.button_select_file = QPushButton("Select File", font=BUTTON_FONT)
        self.button_select_file.setFixedHeight(40)
        self.button_select_file.setStyleSheet("color: white; background-color: #00D632; border-radius: 20px")

        h_layout = QHBoxLayout()
        h_layout.addWidget(self.combo_box)
        h_layout.addWidget(self.button_select_file)

        self.file_label = QLabel(self, text="Selected Folder: ", font=SIMPLE_FONT)

        self.button_generate_hash = QPushButton("Generate Hash", font=BUTTON_FONT)
        self.button_generate_hash.setFixedHeight(40)
        self.button_generate_hash.setStyleSheet("color: white; background-color: #00D632; border-radius: 20px")

        self.button_verify_hash = QPushButton("Verify Hash", font=BUTTON_FONT)
        self.button_verify_hash.setFixedHeight(40)
        self.button_verify_hash.setStyleSheet("color: white; background-color: #00D632; border-radius: 20px")

        self.progress_bar = QProgressBar()

        self.results_frame = QFrame()
        self.results_frame.setFrameStyle(QFrame.Box)
        results_label = QLabel(self.results_frame, text="Results", font=SIMPLE_FONT)
        results_label.setAlignment(Qt.AlignCenter)

        self.table_layout = QHBoxLayout()

        self.match_table = self.make_table()
        self.corrupt_table = self.make_table()
        self.match_table.setHorizontalHeaderLabels(["Match"])
        self.corrupt_table.setHorizontalHeaderLabels(["Corrupt"])
        self.table_layout.addWidget(self.match_table)
        self.table_layout.addWidget(self.corrupt_table)

        self.results_layout = QVBoxLayout()
        self.results_layout.addWidget(results_label)
        self.results_layout.addLayout(self.table_layout)
        self.results_frame.setLayout(self.results_layout)

        # Layout
        layout = QVBoxLayout()
        layout.addLayout(h_layout, 10)
        layout.addWidget(self.file_label)
        layout.addWidget(QLabel())
        layout.addWidget(self.button_generate_hash, 10)
        layout.addWidget(QLabel())
        layout.addWidget(self.button_verify_hash, 10)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.results_frame, 70)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        # Signals
        self.button_select_file.clicked.connect(self.select_file)
        self.button_generate_hash.clicked.connect(self.generate_hash)
        self.button_verify_hash.clicked.connect(self.verify_hash)

    def select_file(self):
        self.folder_path = QFileDialog.getExistingDirectory(self, "Select a folder")
        self.file_label.setText("Selected Folder: " + self.folder_path.replace("/", "\\"))

    def make_table(self):
        # Create the table widget
        table = QTableWidget(self.results_frame)
        table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        table.setColumnCount(1)  # Set the number of columns to 1

        # Set the column to stretch along the whole width of the table
        table.horizontalHeader().setStretchLastSection(True)

        # Add vertical scrollbar to the table
        v_scroll = QAbstractScrollArea.verticalScrollBar(table)
        v_scroll.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)

        # Add horizontal scrollbar to the table
        h_scroll = QAbstractScrollArea.horizontalScrollBar(table)
        h_scroll.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        return table

    def update_progress(self, progress_percentage):
        self.progress_bar.setValue(progress_percentage)

    def generate_hash(self):
        if not os.path.exists("hashes"):
            os.makedirs("hashes")
        if self.folder_path:
            algorithm = self.combo_box.currentText()

            folder_name = os.path.basename(self.folder_path)
            hash_file_name = os.path.join("hashes", f"{folder_name}_{algorithm}.bin")
            if os.path.exists(hash_file_name):
                quit_confirmation = QMessageBox.question(self, 'Confirmation', 'The hash file for the selected folder and algorithm already exists.\nDo you want to over write it?', QMessageBox.Yes | QMessageBox.No)
                if quit_confirmation == QMessageBox.No:
                    return
        else:
            QMessageBox.warning(self, "No Folder Selected", "No folder has been selected for Hash Generation.", QMessageBox.Ok)
            return

        self.hash_generator_thread = HashGenerator(self.folder_path, algorithm)
        self.hash_generator_thread.progress_signal.connect(self.update_progress)
        self.hash_generator_thread.finished_signal.connect(self.finish_generation)
        self.hash_generator_thread.start()

    def finish_generation(self):
        QMessageBox.information(self, "Hash Generation Completed", "Hash Generation for " + self.folder_path + " Completed.")
        self.progress_bar.setValue(0)

    def verify_hash(self):
        if not os.path.exists("hashes"):
            QMessageBox.warning(self, "Hash Files Not Found", 'The folder containing hash files was not found.\nTry checking if the folder named "hashes" exists or if it was mistakenly renamed.', QMessageBox.Ok)
            return
        if self.folder_path:
            folder_name = os.path.basename(self.folder_path)

            algorithm = ""  # Default value if algorithm cannot be determined
            for hash_file in os.listdir("hashes"):
                if folder_name in hash_file:
                    algorithm = hash_file.split("_")[-1].replace(".bin", "")
                    break

            if algorithm == "":
                QMessageBox.warning(self, "Hash File Not Found", "The hash file for the selected folder does not exist.", QMessageBox.Ok)
                return
        else:
            QMessageBox.warning(self, "No Folder Selected", "No folder has been selected for Hash Verification.", QMessageBox.Ok)
            return

        self.hash_generator_thread = HashVerifier(self.folder_path, algorithm, self.match_table, self.corrupt_table)
        self.hash_generator_thread.progress_signal.connect(self.update_progress)
        self.hash_generator_thread.finished_signal.connect(self.finish_verification)
        self.hash_generator_thread.start()

    def finish_verification(self):
        QMessageBox.information(self, "Hash Verification Completed", "Hash Verification for " + self.folder_path + " Completed.")
        self.progress_bar.setValue(0)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FileIntegrityCheckerApp()
    window.show()
    sys.exit(app.exec_())
