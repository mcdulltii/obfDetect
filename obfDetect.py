from idc import *
import idaapi
from idaapi import *
import idautils
import ida_kernwin

from obfDetect import detect

PLUGIN_VERSION = "1.0"
IDAVERISONS = "IDA PRO 7.4+"
AUTHORS = "mcdulltii"
DATE = "2021"

MAX_FUNCTIONS = 50

def banner():
    banner_options = (PLUGIN_VERSION, AUTHORS, DATE, IDAVERISONS)
    banner_titles = "Obfuscation Detection v%s - (c) %s - %s - %s" % banner_options
    # print plugin banner
    print("\n---[" + banner_titles + "]---\n")

banner()

# Obfuscation Detection Handler
class ObfDetectHandler(action_handler_t):
    def __init__(self):
        action_handler_t.__init__(self)

    # Run script when invoked.
    def activate(self, ctx):
        if sum([1 for i in idautils.Functions()]) > MAX_FUNCTIONS:
            detect.partial_heur()
        else:
            detect.all_heur()

    def update(self, ctx):
        return AST_ENABLE_ALWAYS

class obfDetect_plugin_t(plugin_t):
    flags = PLUGIN_FIX
    comment = "Calculates binary obfuscation heuristics"
    help = "Obfuscation Detection"
    wanted_name = "Obfuscation Detection"
    wanted_hotkey = ""

    def editor_menuaction(self):
        action_desc = action_desc_t(
            'my:detectoraction',  # The action name. This acts like an ID and must be unique
            'Obfuscation Detection',  # The action text.
            ObfDetectHandler(),  # The action handler.
            'Ctrl+Shift+H',  # Optional: the action shortcut
            '',  # Optional: the action tooltip (available in menus/toolbar)
            122  # icon number
        )

        # Register the action
        register_action(action_desc)

        attach_action_to_menu(
            'File/Editor...',  # The relative path of where to add the action
            'my:detectoraction',  # The action ID (see above)
            SETMENU_APP)  # We want to append the action after the 'Manual instruction...

        form = ida_kernwin.get_current_widget()
        attach_action_to_popup(form, None, "my:detectoraction", None)

    def init(self):
        """
        This is called by IDA when it is loading the plugin.
        """
        # attempt plugin initialization
        try:
            self._install_plugin()
        # failed to initialize or integrate the plugin, log and skip loading
        except Exception as e:
            form = ida_kernwin.get_current_widget()
            pass
        return PLUGIN_KEEP

    def _install_plugin(self):
        """
        Initialize & integrate the plugin into IDA.
        """
        self.editor_menuaction()
        self._init()

    def run(self, arg = 0):
        # We need the calls again if we wanna load it via File/Plugins/editor
        msg("Obfuscation Detection loaded.\nUse Alt+E hot key to quick load.\n")
        hackish = ObfDetectHandler()
        hackish.activate(self)

    def term(self):
        pass

def PLUGIN_ENTRY():
    return obfDetect_plugin_t()