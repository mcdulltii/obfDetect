from idaapi import *
from idc import *
from idautils import *

from concurrent.futures import ThreadPoolExecutor

from . import MAX_NODES

class CachedThreadPoolExecutor(ThreadPoolExecutor):
    def __init__(self):
        super(CachedThreadPoolExecutor, self).__init__(max_workers=1)

    def submit(self, fn, *args, **extra):
        if self._work_queue.qsize() > 0:
            self._max_workers +=1
        return super(CachedThreadPoolExecutor, self).submit(fn, *args, **extra)

def calc_flattening_score(address):
    score = 0.0
    func_flowchart = FlowChart(get_func(address))
    # number of basic blocks
    num_nodes = sum([1 for _ in func_flowchart])
    # Filter out large functions
    if num_nodes > MAX_NODES:
        return -1

    # method to recursively browse the elements
    def get_children(parent, node, pool):
        for child in node[parent]:
            yield child
            try:
                submit = pool.submit(get_children(child, node, pool))
                for grandchild in submit.result():
                    yield grandchild
            except:
                pass

    # 1: walk over all basic blocks
    func_vec = []
    for block in func_flowchart:
        func_vec.append([block.start_ea, None])
        for succ_block in block.succs():
            func_vec.append([block.start_ea, succ_block.start_ea])
    # 2: get all blocks that are dominated by each basic block
    children = {}
    for p, c in func_vec:
        children.setdefault(p, []).append(c)
    pool = CachedThreadPoolExecutor()
    all_children = {p: list(set([i for i in get_children(p, children, pool) if i != None])) for p in children}
    for element in all_children.keys():
        if element not in all_children[element]:
            all_children[element].append(element)
    # roots = set(children) - set(c for cc in children.values() for c in cc)
    # 3: check for a back edge
    for block in func_flowchart:
        incoming_edges = []
        for vec in func_vec:
            if block.start_ea == vec[1]:
                incoming_edges.append(vec[0])
        try:
            if not any([edge in all_children[block.start_ea] for edge in set(incoming_edges)]):
                continue
        except:
            continue
        # 4: calculate relation of dominated blocks to the blocks in the graph
        score = max(score, len(all_children[block.start_ea])/sum([1 for block in func_flowchart]))
    # return score
    return score


def calc_cyclomatic_complexity(address):
    func_flowchart = FlowChart(get_func(address))
    # number of basic blocks
    num_nodes = sum([1 for _ in func_flowchart])
    # number of edges in the graph
    num_edges = sum([sum([1 for i in block.succs()]) for block in func_flowchart])
    return num_edges - num_nodes + 2


def calc_average_instructions_per_block(address):
    func_flowchart = FlowChart(get_func(address))
    # number of basic blocks
    num_blocks = sum([1 for _ in func_flowchart])
    # number of instructions
    num_instructions = sum([sum([1 for _ in Heads(block.start_ea, block.end_ea)]) for block in func_flowchart])
    return num_instructions / num_blocks