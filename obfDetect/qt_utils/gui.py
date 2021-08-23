from PyQt5 import QtWidgets, uic
import sys
import qasync
import asyncio
from os import environ

def suppress_qt_warnings():
    environ["QT_API"] = "pyqt5"
    environ["QT_DEVICE_PIXEL_RATIO"] = "0"
    environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
    environ["QT_SCREEN_SCALE_FACTORS"] = "1"
    environ["QT_SCALE_FACTOR"] = "1"

class Ui(QtWidgets.QMainWindow):
    def __init__(self):
        super(Ui, self).__init__() # Call the inherited classes __init__ method
        uic.loadUi('window.ui', self) # Load the .ui file

def show_gui():
    # Suppress warnings
    suppress_qt_warnings()

    app = QtWidgets.QApplication(sys.argv)
    window = Ui() # Initialize UI

    # Add stylesheet
    try:
        import qdarkstyle
        app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
    except ModuleNotFoundError:
        pass

    # Show UI
    window.show()
    app.exec_()

    # Initialize async
    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)
