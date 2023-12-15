import logging

from explorer import explorer

logger = logging.getLogger(__name__)


def prepare_cfg():
    """
    Generates a CFG based on the init state.
    """
    init_state = explorer.BasicBlockExplorer().get_init_state()
    cfg = init_state.project.analyses.CFGFast(function_starts=[init_state.addr])
    return cfg


def simplify_cfg_to_tree(initial_node, depth_limit=100000):
    node_list = {initial_node: 0}

    def _add_succ(succ_list, limit):
        if limit > 0:
            for s in succ_list:
                if s not in node_list:
                    node_list[s] = 0
                    _add_succ(s.successors, limit - 1)

    _add_succ(initial_node.successors, depth_limit)

    return node_list


def export_to_dot(nodes, filepath):
    node_list = list(nodes)
    dot = 'digraph G {\n'

    for i in range(len(node_list)):
        # Display this node either as colored red or with a tooltip showing # of hits
        if nodes[node_list[i]] == 0:
            dot += f'"{node_list[i].name}" [color=red]\n'
        else:
            dot += f'"{node_list[i].name}" [label="{node_list[i].name}\n{nodes[node_list[i]]} hits"]\n'

        # Loop over successors and add transitions
        for s in node_list[i].successors:
            if s not in node_list[0:i + 1]:
                dot += f'"{node_list[i].name}" -> "{s.name}";\n'

    dot += '\n}'

    with open(filepath, 'w') as f:
        f.writelines(dot)
