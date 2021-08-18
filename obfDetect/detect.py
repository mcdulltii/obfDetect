from .obfuscation_detection.heuristics import *

def all_heur():
    print('\n')
    find_flattened_functions()
    find_complex_functions(partial=False)
    find_large_basic_blocks(partial=False)
    return

def partial_heur():
    print('\n')
    find_complex_functions()
    find_large_basic_blocks()
    return

def flat_heur():
    print('\n')
    find_flattened_functions()
    return
