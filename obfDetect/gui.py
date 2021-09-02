from PyQt5 import QtCore, QtGui, QtWidgets
from idaapi import PluginForm, jumpto, set_name
import idaapi
from idautils import Functions

# INIT variables
MAX_NODES = 50

from .obfuscation_detection.heuristics import *
from .obfuscation_detection.utils import *

# Handle keyPress events for QTableWidget
class CustomQTableWidget(QtWidgets.QTableWidget):
    def __init__(self):
        QtWidgets.QTableWidget.__init__(self)
        # Bool if user has edited a cell
        self.editing = False
    def event(self, event):
        if event.type() == QtCore.QEvent.KeyRelease and event.key() == QtCore.Qt.Key_N:
            # Enable edit if keyPress is 'n'
            self.editing = True
            self.edit(self.currentIndex())
        return QtWidgets.QTableWidget.event(self, event)

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
        self.table = CustomQTableWidget()
        self.table.setEditTriggers(QtWidgets.QTableWidget.NoEditTriggers)
        self.table.doubleClicked.connect(self.goto_address)
        self.table.itemChanged.connect(self.changed_cell)
        # Current row count for single function heuristics
        self.currentRowCount = [0, 0]
        # Compare with previous heuristic button selection
        self.previousHeurFunc = None
        self.table.setRowCount(self.currentRowCount[1])
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
        # Set PluginForm layout
        self.parent.setLayout(layout)

    def heuristic_selection(self):
        # Switch case for heuristicButton selection
        self.heurSelection = self.heuristicButtonGroup.checkedButton().text()
        if self.previousHeurFunc != None and self.previousHeurFunc != self.heurSelection:
            self.currentRowCount = [0, 0]
        self.previousHeurFunc = self.heurSelection
        if self.heurSelection in [self.heuristicNames[0], self.heuristicNames[3]]:
            self.maxCheck.setEnabled(True)
        else:
            self.maxCheck.setEnabled(False)
        if self.heurSelection == self.heuristicNames[3]:
            # Only allow all functions for overlapping heuristic
            self.singleFuncButton.setEnabled(False)
            self.singleFuncText.setEnabled(False)
            self.allFuncButton.setChecked(True)
        else:
            self.singleFuncButton.setEnabled(True)
            self.singleFuncText.setEnabled(True)
            self.allFuncButton.setChecked(False)
        self.numfunc_selection()
        self.check_maxNum()

    def numfunc_selection(self):
        # Returns 1 if single function, else 0
        self.numFuncSelection = 1 if self.singleFuncButton.isChecked() else 0
        if not self.numFuncSelection:
            self.allFuncButton.setChecked(True)
        if self.currentRowCount[0] and self.numFuncSelection:
            self.currentRowCount = [0, 0]

    def check_maxNum(self):
        self.maxNum.setEnabled(self.maxCheck.checkState())

    @staticmethod
    def parse_field(funcAddress):
        if funcAddress != -1:
            # Try to parse funcAddress as hex or int value from string
            try:
                if funcAddress[:2] == '0x' or funcAddress[-1] == 'h':
                    funcAddress = int(funcAddress, 16)
                else:
                    funcAddress = int(funcAddress)
            except:
                funcAddress = None
        return funcAddress

    def goto_address(self):
        # Redirect double-clicked cell function address to CFG
        selected = self.table.currentItem()
        try:
            # Only allow first and second column
            if selected.column() == 0:
                funcAddress = self.parse_field(selected.text())
            elif selected.column() == 1:
                funcAddress = self.parse_field(self.table.itemAt(selected.row(), 0).text())
            # Jump to selected function address
            jumpto(funcAddress)
        except:
            pass

    def changed_cell(self, item):
        # Handle modified cell
        func_name = item.text()
        try:
            func_addr = int(self.table.itemAt(item.row(), 0).text(), 16)
            # Check modified function is valid and different
            if get_func_name(func_addr) != func_name and len(func_name) > 0 and self.table.editing:
                # Rename function at function address
                set_name(func_addr, func_name, idaapi.SN_FORCE)
                # Toggle bool to disable function renaming
                self.table.editing = False
        except:
            pass

    def run_heur(self):
        global MAX_NODES
        if not self.currentRowCount[0]:
            self.table.setRowCount(0)
        heuristicFunctions = [find_flattened_functions, \
                              find_complex_functions, \
                              find_large_basic_blocks, \
                              find_instruction_overlapping, \
                              calc_flattening_score, \
                              calc_cyclomatic_complexity, \
                              calc_average_instructions_per_block]
        heuristicFunctionOffset = 4
        # Check if single function has been selected
        funcAddress = self.singleFuncText.toPlainText() if self.numFuncSelection else -1
        # Function address only in hex or int string
        funcAddress = self.parse_field(funcAddress)

        # Verify funcAddress in IDA's listed functions
        if funcAddress not in Functions() and funcAddress != -1:
            funcAddress = None

        # Index of heuristic function
        funcIndex = self.heuristicNames.index(self.heurSelection)
        QtFlags = QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled
        if funcAddress == -1:
            self.currentRowCount = [0, 0]
            # Disable sorting
            self.table.setSortingEnabled(False)
            # Check for node limit
            if self.maxCheck.checkState():
                maxNumtext = self.parse_field(self.maxNum.text())
                if maxNumtext != None:
                    MAX_NODES = maxNumtext
            # If all function selected
            heur_list = heuristicFunctions[funcIndex]()
            if len(heur_list) == 0:
                # If no result found from heuristic function
                self.table.setRowCount(1)
                self.table.setItem(0, 0, QtWidgets.QTableWidgetItem("None found"))
                self.table.setItem(0, 1, QtWidgets.QTableWidgetItem("None found"))
                self.table.setItem(0, 2, QtWidgets.QTableWidgetItem("None found"))
            else:
                # If result found from heuristic function
                self.table.setRowCount(len(heur_list))
                for index, func_addr in enumerate(heur_list):
                    item_addr = QtWidgets.QTableWidgetItem(func_addr)
                    item_addr.setFlags(QtFlags)
                    self.table.setItem(index, 0, item_addr)
                    item = QtWidgets.QTableWidgetItem(get_func_name(self.parse_field(func_addr)))
                    item.setFlags( QtFlags | QtCore.Qt.ItemIsEditable )
                    self.table.setItem(index, 1, item)
                    heur_score = "Skipped" if heur_list[func_addr] in [-1, hex(-1)] else str(heur_list[func_addr])
                    item_score = QtWidgets.QTableWidgetItem(heur_score)
                    item_score.setFlags(QtFlags)
                    self.table.setItem(index, 2, item_score)
        elif funcAddress == None:
            self.currentRowCount = [0, 0]
            # Disable sorting
            self.table.setSortingEnabled(False)
            # If function address parsed wrongly
            self.table.setRowCount(1)
            self.table.setItem(0, 0, QtWidgets.QTableWidgetItem("Error"))
            self.table.setItem(0, 1, QtWidgets.QTableWidgetItem("Error"))
            self.table.setItem(0, 2, QtWidgets.QTableWidgetItem("Error"))
        else:
            # If single function selected
            savedCount = self.currentRowCount[1]
            if not self.table.findItems(hex(funcAddress), QtCore.Qt.MatchFixedString | QtCore.Qt.MatchCaseSensitive):
                # Only insert new data (prevent duplicates)
                if not self.currentRowCount[0]:
                    self.table.setRowCount(savedCount + 1)
                else:
                    self.table.insertRow(savedCount)
                # Enable sorting
                self.table.setSortingEnabled(True)
                self.currentRowCount[0] = 1
                self.currentRowCount[1] += 1
                heur_score = heuristicFunctions[funcIndex + heuristicFunctionOffset](funcAddress)
                heur_score = "Skipped" if heur_score == -1 else str(heur_score)
                item_addr = QtWidgets.QTableWidgetItem(hex(funcAddress))
                item_addr.setFlags(QtFlags)
                self.table.setItem(savedCount, 0, item_addr)
                item = QtWidgets.QTableWidgetItem(get_func_name(funcAddress))
                item.setFlags( QtFlags | QtCore.Qt.ItemIsEditable)
                self.table.setItem(savedCount, 1, item)
                item_score = QtWidgets.QTableWidgetItem(heur_score)
                item_score.setFlags(QtFlags)
                self.table.setItem(savedCount, 2, item_score)

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
