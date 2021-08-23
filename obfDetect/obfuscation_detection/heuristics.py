from idaapi import *
from idc import *
from idautils import *

from math import ceil

from . import MAX_NODES
from .utils import *
from ..mcsema_disass.util import *
from ..mcsema_disass.flow import get_direct_branch_target


def create_func_dict(detection_function):
    func_dict = {}
    for ea in Functions():
        func_addr = hex(ea)
        func_complexity = detection_function(ea)
        func_dict[func_addr] = func_complexity
    return func_dict


def find_flattened_functions():
    print("=" * 80)
    print("Control Flow Flattening")
    # Filter functions by flattening score
    func_dict = create_func_dict(calc_flattening_score)
    filtered_functions = dict(filter(lambda score: score >= 0.9, func_dict.values()))
    # Print function and score
    if len(filtered_functions) == 0:
        print("NOTE: Functions are likely not flattened")
        func_list = func_dict
    else:
        func_list = filtered_functions
    for func_addr in func_list:
        func_name = get_func_name(int(func_addr, 16))
        if func_list[func_addr] != -1:
            print(f"Function {func_addr} ({func_name}) has a flattening score of {func_list[func_addr]}.")
        else:
            print(f"Function {func_addr} ({func_name}) skipped.")


def find_complex_functions(partial=True):
    print("=" * 80)
    print("Cyclomatic Complexity")
    # sort functions by cyclomatic complexity
    func_dict = create_func_dict(calc_cyclomatic_complexity)
    sorted_functions = dict(sorted(func_dict.items(), key=lambda item: item[1]))

    # bound to print only the top 10%
    bound = ceil(((sum([1 for _ in Functions()]) * 10) / 100))

    # print top 10% (iterate in descending order)
    func_list = list(sorted_functions.keys())[::-1][:bound] if partial else list(sorted_functions.keys())[::-1]
    for func_addr in func_list:
        func_name = get_func_name(int(func_addr, 16))
        print(f"Function {func_addr} ({func_name}) has a cyclomatic complexity of {sorted_functions[func_addr]}.")


def find_large_basic_blocks(partial=True):
    print("=" * 80)
    print("Large Basic Blocks")
    # sort functions by size of blocks
    func_dict = create_func_dict(calc_average_instructions_per_block)
    sorted_functions = dict(sorted(func_dict.items(), key=lambda item: item[1]))

    # bound to print only the top 10%
    bound = ceil(((sum([1 for _ in Functions()]) * 10) / 100))

    # print top 10% (iterate in descending order)
    func_list = list(sorted_functions.keys())[::-1][:bound] if partial else list(sorted_functions.keys())[::-1]
    for func_addr in func_list:
        func_name = get_func_name(int(func_addr, 16))
        print(f"Basic blocks in function {func_addr} ({func_name}) contain on average {ceil(sorted_functions[func_addr])} instructions.")


def find_instruction_overlapping():
    print("=" * 80)
    print("Instruction Overlapping")

    # Highlight color
    def color_insn(ea, color = 0xFFFF00):
        current_color = get_item_color(ea)
        if current_color == color:
            set_item_color(ea, DEFCOLOR)
        elif current_color == DEFCOLOR:
            set_item_color(ea, color)

    # set of addresses
    seen = {}
    functions_with_overlapping = set()

    def walk_functions(cycle = False):
        nonlocal seen
        nonlocal functions_with_overlapping

        # check for direct and indirect jumps
        def check_insn(address):
            nonlocal seen
            nonlocal functions_with_overlapping
            inst = DecodeInstruction(address)
            # Instruction mneumonic is jmp or call
            if is_function_call(inst) or is_direct_function_call(inst) or is_indirect_function_call(inst) or \
                is_direct_jump(inst) or is_indirect_jump(inst) or \
                is_conditional_jump(inst) or is_unconditional_jump(inst) or is_return(inst):
                # Forcefully retrieve jmp or call address
                targ_address = get_direct_branch_target(inst)
                targ_func = get_func(targ_address)
                if targ_address != None and targ_func != None:
                    # Ensure target address is within code section
                    if targ_func.start_ea in Functions():
                        # seen for the first time
                        if targ_address not in seen:
                            seen[targ_address] = 1
                        # seen before and not marked as instruction beginning
                        elif seen[targ_address] == 0:
                            functions_with_overlapping.add(targ_func.start_ea)
                            color_insn(targ_address)

        # walk over all functions
        for ea in Functions():
            # Skip function if current function is too large
            func_length = sum([1 for _ in FlowChart(get_func(ea))])
            if func_length > MAX_NODES:
                continue
            # walk over all instructions
            for (startea, endea) in Chunks(ea):
                for address in Heads(startea, endea):
                    address_bak = address
                    # seen for the first time
                    if address not in seen:
                        # mark as instruction beginning
                        seen[address] = 1
                    # seen before and not marked as instruction beginning
                    elif seen[address] == 0:
                        functions_with_overlapping.add(startea)
                        color_insn(address)
                    if cycle:
                        # follow jmp and call instructions
                        check_insn(address)
                    else:
                        # walk over instruction length and mark bytes as seen
                        insn = insn_t()
                        for _ in range(1, decode_insn(insn, address)):
                            address += 1
                            # if seen before and marked as instruction beginning
                            if address in seen and seen[address] == 1:
                                functions_with_overlapping.add(startea)
                                color_insn(address)
                            else:
                                seen[address] = 0
        if cycle:
            walk_functions(cycle = False)

    walk_functions(cycle = True)
    if len(functions_with_overlapping) > 0:
        for address in sorted(functions_with_overlapping):
            print(f"Overlapping instructions in function {hex(address)} ({get_func_name(address)}).")
    else:
        print("No overlapping instructions found in binary.")
