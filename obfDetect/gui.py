from PyQt5 import QtCore, QtGui, QtWidgets
from idaapi import PluginForm, jumpto
import qasync
import asyncio
import re

from .obfuscation_detection.heuristics import *
from .obfuscation_detection.utils import *

class obfDetectForm(PluginForm):
    def OnCreate(self, form):
        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

    def PopulateForm(self):
        # Create layout
        layout = QtWidgets.QVBoxLayout()
        self.parent.setSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.MinimumExpanding)
        self.parent.setStyleSheet(''' font-size: 12px; ''')

        # Create table
        self.table = QtWidgets.QTableWidget()
        self.table.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
        self.table.doubleClicked.connect(self.goto_address)
        self.currentRowCount = 0
        self.table.setRowCount(self.currentRowCount)
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Function Address", "Function Name", "Heuristic"])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QtWidgets.QHeaderView.Stretch)

        # Create heuristic button group box
        self.heuristicGroupBox = QtWidgets.QGroupBox("Heuristic Functions")
        heuristic_layout = QtWidgets.QHBoxLayout()
        self.heuristicButtonGroup = QtWidgets.QButtonGroup()

        # Create heuristic buttons
        self.heuristicNames = ["Control-Flow Flattening", \
                               "Cyclomatic Complexity", \
                               "Basic Block Size", \
                               "Instruction Overlapping"]
        self.heuristicFunctions = [QtWidgets.QRadioButton() for _ in range(len(self.heuristicNames))]
        for index, each in enumerate(self.heuristicFunctions):
            each.setText(self.heuristicNames[index])
            each.clicked.connect(self.heuristic_selection)
            self.heuristicButtonGroup.addButton(each)
            heuristic_layout.addWidget(each)
        self.heuristicGroupBox.setLayout(heuristic_layout)

        # Create selection button group box
        self.numFuncGroupBox = QtWidgets.QGroupBox("Number of Functions")
        self.numFuncGroupBox.setMaximumHeight(100)
        numFunc_layout = QtWidgets.QVBoxLayout()
        singleFunc_layout = QtWidgets.QHBoxLayout()
        self.numFuncButtonGroup = QtWidgets.QButtonGroup()

        # Create selection buttons
        self.singleFuncButton = QtWidgets.QRadioButton()
        self.singleFuncButton.setText("Single Function")
        self.singleFuncButton.clicked.connect(self.numfunc_selection)
        self.numFuncButtonGroup.addButton(self.singleFuncButton)
        singleFunc_layout.addWidget(self.singleFuncButton)
        self.singleFuncText = QtWidgets.QTextEdit()
        self.singleFuncText.setMaximumHeight(30)
        self.singleFuncText.setAlignment(QtCore.Qt.AlignVCenter)
        singleFunc_layout.addWidget(self.singleFuncText)
        numFunc_layout.addLayout(singleFunc_layout)
        self.allFuncButton = QtWidgets.QRadioButton()
        self.allFuncButton.setText("All Functions (Filtered for lag)")
        self.allFuncButton.clicked.connect(self.numfunc_selection)
        self.numFuncButtonGroup.addButton(self.allFuncButton)
        numFunc_layout.addWidget(self.allFuncButton)
        self.numFuncGroupBox.setLayout(numFunc_layout)

        # Miscellaneous Widgets
        self.miscGroupBox = QtWidgets.QGroupBox("Execution")
        miscFunc_layout = QtWidgets.QGridLayout()
        maxFunc_layout = QtWidgets.QVBoxLayout()
        self.maxCheck = QtWidgets.QCheckBox()
        self.maxCheck.setText("Max Node per Function")
        self.maxCheck.clicked.connect(self.check_maxNum)
        self.maxCheck.setChecked(False)
        maxFunc_layout.addWidget(self.maxCheck)
        self.maxNum = QtWidgets.QSpinBox()
        self.maxNum.setMaximumWidth(200)
        self.maxNum.setMinimum(1)
        self.maxNum.setMaximum(200)
        self.maxNum.setEnabled(False)
        maxFunc_layout.addWidget(self.maxNum)
        execFunc_layout = QtWidgets.QVBoxLayout()
        self.runButton = QtWidgets.QPushButton()
        self.runButton.setText("Run")
        self.runButton.clicked.connect(self.run_heur)
        execFunc_layout.addWidget(self.runButton)
        self.exportButton = QtWidgets.QPushButton()
        self.exportButton.setText("Export")
        self.exportButton.clicked.connect(self.export)
        execFunc_layout.addWidget(self.exportButton)
        miscFunc_layout.addLayout(maxFunc_layout, 0, 0, 0, 0)
        miscFunc_layout.addLayout(execFunc_layout, 0, 1, 0, 1)
        self.miscGroupBox.setLayout(miscFunc_layout)

        layout.addWidget(self.table)
        layout.addWidget(self.heuristicGroupBox)
        layout.addWidget(self.numFuncGroupBox)
        layout.addWidget(self.miscGroupBox)
        # make our created layout the dialogs layout
        self.parent.setLayout(layout)

    def heuristic_selection(self):
        self.heurSelection = self.heuristicButtonGroup.checkedButton().text()
        if self.heurSelection == self.heuristicNames[0]:
            self.allFuncButton.setEnabled(False)
            self.singleFuncButton.setChecked(True)
        else:
            self.allFuncButton.setEnabled(True)
            self.singleFuncButton.setChecked(False)
        if self.heurSelection == self.heuristicNames[3]:
            self.singleFuncButton.setEnabled(False)
            self.singleFuncText.setEnabled(False)
            self.allFuncButton.setChecked(True)
        else:
            self.singleFuncButton.setEnabled(True)
            self.singleFuncText.setEnabled(True)
            self.allFuncButton.setChecked(False)
        self.numfunc_selection()

    def numfunc_selection(self):
        # Returns 1 if single function, else 0
        self.numFuncSelection = 1 if self.singleFuncButton.isChecked() else 0

    def check_maxNum(self):
        self.maxNum.setEnabled(self.maxCheck.checkState())

    @staticmethod
    def parse_field(funcAddress):
        if funcAddress != -1:
            try:
                if funcAddress[:2] == '0x' or funcAddress[-1] == 'h':
                    funcAddress = int(funcAddress, 16)
                # elif re.search('[a-zA-Z]', the_string):
                    # funcAddress = 
                else:
                    funcAddress = int(funcAddress)
            except:
                funcAddress = None
        return funcAddress

    def goto_address(self):
        selected = self.table.currentItem()
        if selected.column() in [0, 1]:
            funcAddress = self.parse_field(selected.text())
            try:
                jumpto(funcAddress)
            except:
                pass

    def run_heur(self):
        self.table.setRowCount(0)
        heuristicFunctions = [find_flattened_functions, \
                              find_complex_functions, \
                              find_large_basic_blocks, \
                              find_instruction_overlapping, \
                              calc_flattening_score, \
                              calc_cyclomatic_complexity, \
                              calc_average_instructions_per_block]
        heuristicFunctionOffset = 4
        funcAddress = self.singleFuncText.toPlainText() if self.numFuncSelection else -1
        funcAddress = self.parse_field(funcAddress)
        funcIndex = self.heuristicNames.index(self.heurSelection)
        if funcAddress == -1:
            heur_list = heuristicFunctions[funcIndex]()
            if len(heur_list) == 0:
                self.table.setRowCount(1)
                self.table.setItem(0, 0, QtWidgets.QTableWidgetItem("None found"))
                self.table.setItem(0, 1, QtWidgets.QTableWidgetItem("None found"))
                self.table.setItem(0, 2, QtWidgets.QTableWidgetItem("None found"))
            else:
                self.table.setRowCount(len(heur_list))
                for index, func_addr in enumerate(heur_list):
                    self.table.setItem(index, 0, QtWidgets.QTableWidgetItem(func_addr))
                    self.table.setItem(index, 1, QtWidgets.QTableWidgetItem(get_func_name(int(func_addr, 16))))
                    if funcIndex != 3:
                        heur_score = "Skipped" if heur_list[func_addr] == -1 else str(heur_list[func_addr])
                        self.table.setItem(index, 2, QtWidgets.QTableWidgetItem(heur_score))
        elif funcAddress == None:
            self.table.setRowCount(1)
            self.table.setItem(0, 0, QtWidgets.QTableWidgetItem("Error"))
            self.table.setItem(0, 1, QtWidgets.QTableWidgetItem("Error"))
            self.table.setItem(0, 2, QtWidgets.QTableWidgetItem("Error"))
        else:
            savedCount = self.currentRowCount
            self.currentRowCount += 1
            self.table.setRowCount(self.currentRowCount)
            heur_score = heuristicFunctions[funcIndex + heuristicFunctionOffset](funcAddress)
            heur_score = "Skipped" if heur_score == -1 else str(heur_score)
            self.table.setItem(savedCount, 0, QtWidgets.QTableWidgetItem(funcAddress))
            self.table.setItem(savedCount, 1, QtWidgets.QTableWidgetItem(get_func_name(int(funcAddress, 16))))
            self.table.setItem(savedCount, 2, QtWidgets.QTableWidgetItem(heur_score))

    def export(self):
        pass

    def OnClose(self, form):
        pass

def show_gui():
    app = QtWidgets.QApplication.instance()
    window = obfDetectForm() # Initialize UI

    # Add stylesheet
    try:
        import qdarkstyle
        app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
    except ModuleNotFoundError:
        pass

    # Show UI
    window.Show("Obfuscation Detection")

    # Initialize async
    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)
