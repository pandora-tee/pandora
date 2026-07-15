import logging
import angr
import claripy

from typing import Any, Sequence
from parsimonious.nodes import Node, NodeVisitor
from parsimonious.grammar import Grammar
from pathlib import Path
from archinfo import Arch
from angr.sim_state import SimState
from functools import partial

from sdks.SymbolManager import SymbolManager

logger = logging.getLogger(__file__)


class ScriptVisitor(NodeVisitor):
    def visit_script(self, node: Node, visited_children: Sequence[Any]):
        output = []
        for child in visited_children:
            if 'action_n' not in child:
                child['action_n'] = 1
            output.append(child)
        return output
    
    def visit_concr(self, node: Node, visited_children: Sequence[Any]):
        output = self.generic_visit(node, visited_children)
        output['concretize'] = True
        return output
    
    def visit_set_ac(self, node: Node, visited_children: Sequence[Any]):
        output = self.generic_visit(node, visited_children)
        output['set'] = True
        return output
    
    def visit_expr(self, node: Node, visited_children: Sequence[Any]):
        output = self.generic_visit(node, visited_children)
        if 'register' not in output:
            output['register'] = None
        return output

    def visit_memory(self, node: Node, visited_children: Sequence[Any]):
        output = self.generic_visit(node, visited_children)
        output['memory'] = True
        return output
    
    def visit_symbol(self, node: Node, visited_children: Sequence[Any]):
        output = self.generic_visit(node, visited_children)
        output['symbol_name'] = output.pop('name')
        output['symbol'] = True
        return output
    
    def visit_val(self, node: Node, visited_children: Sequence[Any]):
        output = self.generic_visit(node, visited_children)
        if 'size' in output:
            output['bv_value'] = output.pop('size')
        return output
    
    def visit_symbolic(self, node: Node, visited_children: Sequence[Any]):
        output = self.generic_visit(node, visited_children)
        output['symbolic_name'] = output.pop('name')
        output['symbolic'] = True
        return output
    
    def visit_register(self, node: Node, visited_children: Sequence[Any]):
        return {'register': node.full_text[node.start: node.end]}
    
    def visit_register_offset(self, node: Node, visited_children: Sequence[Any]):
        output = self.generic_visit(node, visited_children)
        if 'operation' not in output:
            output['operation'] = 1
        output['offset'] = output.pop('size') * output.pop('operation')
        return output

    def visit_size(self, node: Node, visited_children: Sequence[Any]):
        base = 16 if node.full_text[node.start: node.end].startswith('0x') else 10
        return {'size': int(node.full_text[node.start: node.end], base)}

    def visit_arbinop(self, node: Node, visited_children: Sequence[Any]):
        if node.full_text[node.start: node.end] == '+':
            return {'operation': 1}
        elif node.full_text[node.start: node.end] == '-':
            return {'operation': -1}
        return {'operation': 0}

    def visit_hook(self, node: Node, visited_children: Sequence[Any]):
        output = self.generic_visit(node, visited_children)
        output['hook_addr'] = output.pop('size')
        return output
    
    def visit_nb(self, node: Node, visited_children: Sequence[Any]):
        output = self.generic_visit(node, visited_children)

        output['action_n'] = output.pop('size')
        return output
    
    def visit_name(self, node: Node, visited_children: Sequence[Any]):
        return {'name': node.full_text[node.start: node.end]}

    def visit_eenter(self, node: Node, visited_children: Sequence[Any]):
        return {'eenter': True, 'hook_addr': 0}

    def visit_eexit(self, node: Node, visited_children: Sequence[Any]):
        return {'exit': True, 'hook_addr': 0}

    def generic_visit(self, node: Node, visited_children: Sequence[Any]):
        output = {}
        for child in visited_children:
            output.update(child)
        return output


class ScriptManager:
    def __init__(self, list_script_files: list[Path], arch: Arch, init_state: SimState) -> None:
        init_state.globals['to_concretize'] = {}
        self.mem_endness = arch.memory_endness

        registers = arch.register_names.values()
        self.grammar = Grammar(
            fr"""
                script          = (action sl*)+

                action          = concr 
                                / set_ac


                concr           = concretize expr alias? of size when event
                set_ac          = set expr to val of size when event 

                expr            = register 
                                / memory
                                / symbol
                
                memory          = "memory(" space register_offset space rpar
                symbol          = "symbol(" space name space rpar

                val             = symbolic
                                / size

                symbolic        = "symbolic(" space name space rpar

                alias           = " alias " name

                event           =  hook 
                                    / eenter 
                                    / eexit
                
                                    
                hook            = addr size space nb? 
                nb              = lpar space ntimes size space rpar
                eenter          = "eenter"
                eexit           = "eexit"
                                
                register        = ~r"({'|'.join(registers)})"
                register_offset = (register space arbinop space)? size
                size            = ~r"\b(0x[0-9a-fA-F]+|[0-9]+)\b"

                arbinop         = ~r"(\+|-)"

                lpar            = "("
                rpar            = ")"
                space           = " "?
                sl              = "\n"?
                name            = ~r"\w+"


                set             = "set "
                to              = " to "
                concretize      = "concretize "
                of              = " of size "
                when            = " when "
                addr            = "addr="
                ntimes          ="n="
            """
        )

        for script in list_script_files:
            output = self.parse_script_file(script)
            for script_entry in output:
                print(script_entry)
                self.apply_script_concretizer(script_entry, init_state)
        init_state.inspect.b('eexit', when=angr.BP_BEFORE, action=self.callback_eexit)
            

    def parse_script_file(self, filename: Path):
        logger.info(f'Going to parse {filename}')
        with open(filename) as sf:
            parsed_script = self.grammar.parse(sf.read().strip())

            sv = ScriptVisitor()
            result = sv.visit(parsed_script)
            return result
        

    def apply_script_concretizer(self, conc: dict, init_state: SimState):
        if 'concretize' in conc and conc['concretize']:
            if 'memory' in conc and conc['memory']:
                if 'name' not in conc:
                    if conc['register'] is not None:
                        conc['name'] = f"{conc['register']}_{hex(conc['offset'])}_{conc['size']}_{conc['action_n']}_{hex(conc['hook_addr'])}_conc"
                    else:
                        conc['name'] = f"{hex(conc['offset'])}_{conc['size']}_{conc['action_n']}_{hex(conc['hook_addr'])}_conc"
                complete_func = partial(
                    self.construct_to_concretize_memory, 
                    conc['name'],
                    conc['register'], 
                    conc['offset'], 
                    conc['size'],
                    conc['action_n'],
                    conc['hook_addr']
                )  
            elif 'symbol' in conc and conc['symbol']:    
                if 'name' not in conc:
                    conc['name'] = f'{conc['symbol_name']}_conc'
                
                complete_func = partial(
                    self.construct_to_concretize_memory, 
                    conc['name'],
                    conc['register'], 
                    SymbolManager().symbol_to_addr(conc['symbol_name']), 
                    conc['size'],
                    conc['action_n'],
                    conc['hook_addr']
                )     
            else:
                if 'name' not in conc:
                    conc['name'] = f"{conc['register']}_{conc['action_n']}_{hex(conc['hook_addr'])}_conc"
                complete_func = partial(
                    self.construct_to_concretize_reg,
                    conc['name'], 
                    conc['register'], 
                    conc['action_n'],
                    conc['hook_addr']
                )
        elif 'set' in conc and conc['set']:
            if 'symbolic' in conc and conc['symbolic']:
                    bv = claripy.BVS(conc['symbolic_name'], conc['size'])
            else:
                bv = claripy.BVV(conc['bv_value'], conc['size'])

            if 'memory' in conc and conc['memory']:
                if 'name' not in conc:
                    if conc['register'] is not None:
                        conc['name'] = f"{conc['register']}_{hex(conc['offset'])}_{conc['size']}_{conc['action_n']}_{hex(conc['hook_addr'])}_set"
                    else:
                        conc['name'] = f"{hex(conc['offset'])}_{conc['size']}_{conc['action_n']}_{hex(conc['hook_addr'])}_set"
                complete_func = partial(
                    self.construct_to_set_memory, 
                    conc['name'],
                    conc['register'], 
                    conc['offset'], 
                    conc['size'],
                    conc['action_n'],
                    conc['hook_addr'],
                    bv
                )  
            elif 'symbol' in conc and conc['symbol']:    
                if 'name' not in conc:
                    conc['name'] = f'{conc['symbol_name']}_set'
                
                complete_func = partial(
                    self.construct_to_set_memory, 
                    conc['name'],
                    conc['register'], 
                    SymbolManager().symbol_to_addr(conc['symbol_name']), 
                    conc['size'],
                    conc['action_n'],
                    conc['hook_addr'],
                    bv
                )     
            else:
                conc['name'] = f"{conc['register']}_{conc['action_n']}_{hex(conc['hook_addr'])}_set"
                complete_func = partial(
                    self.construct_to_set_reg,
                    conc['name'], 
                    conc['register'], 
                    conc['action_n'],
                    conc['hook_addr'],
                    bv
                )



        if 'eenter' in conc and conc['eenter']:
            wrapper = partial(
                self.callback_wrapper,
                complete_func,
                True,
                False
            )
            init_state.inspect.b('eenter', when=angr.BP_AFTER, action=wrapper)
        elif 'eexit' in conc and conc['eexit']:
            wrapper = partial(
                self.callback_wrapper,
                complete_func,
                False,
                True
            )
            init_state.inspect.b('eexit', when=angr.BP_BEFORE, action=wrapper)
        else:
            wrapper = partial(
                self.callback_wrapper,
                complete_func,
                False,
                False
            )
            init_state.inspect.b('engine_process', when=angr.BP_BEFORE, action=wrapper)

            
    def construct_to_concretize_memory(self, name, register, offset, size, action_n, hook_addr, eenter, eexit, state: SimState):
        if state.addr == hook_addr or eenter or eexit:
            action_name = f"action_n_{name}"
            if not action_name in state.globals:
                state.globals[action_name] = 1
            else:
                state.globals[action_name] += 1

            if state.globals[action_name] != action_n:
                return
            
            logger.info(f"Going to conretize {name} {state}")

            if register is not None:
                if state.regs.get(register).length:
                    mem_address = state.regs.get(register) + claripy.BVV(offset, state.regs.get(register).length)      

                    state.globals['to_concretize'] = state.globals['to_concretize'].copy()
                    state.globals['to_concretize'][name] = (mem_address, size), 1
                else:
                    logger.warning("Couldn't create the variable to concretize")
                    return 
            else:
                mem_address = claripy.BVV(offset, size)
                state.globals['to_concretize'] = state.globals['to_concretize'].copy()
                state.globals['to_concretize'][name] = (mem_address, int(size / 8)), 1


    def construct_to_concretize_reg(self, name, register, action_n, hook_addr, eenter, eexit, state: SimState):
        if state.addr == hook_addr or eenter or eexit:
            action_name = f"action_n_{name}"
            if not action_name in state.globals:
                state.globals[action_name] = 1
            else:
                state.globals[action_name] += 1

            if state.globals[action_name] != action_n:
                return

            logger.info(f"Going to conretize {name} {state}")

            state.globals['to_concretize'] = state.globals['to_concretize'].copy()
            if isinstance(state.regs.get(register).concrete_value, int):
                state.globals['to_concretize'][name] = state.regs.get(register).concrete_value, 0
            else:
               # Pay attention to conflicts with Pandora's plugins renaming of registers
               state.globals['to_concretize'][name] = state.regs.get(register).concrete_value, 2

    
    def construct_to_set_memory(self, name, register, offset, size, action_n, hook_addr, bv, eenter, eexit, state: SimState):
        if state.addr == hook_addr or eenter or eexit:
            action_name = f"action_n_{name}"
            if not action_name in state.globals:
                state.globals[action_name] = 1
            else:
                state.globals[action_name] += 1

            if state.globals[action_name] != action_n:
                return
            
            logger.info(f"Going to set {name} {state}")

            if register is not None:
                if state.regs.get(register).length:
                    mem_address = state.regs.get(register) + claripy.BVV(offset, state.regs.get(register).length)
                else:
                    logger.warning("Couldn't create the variable to concretize")
                    return 
            else:
                mem_address = claripy.BVV(offset, size)

            state.memory.store(mem_address, bv, endness=self.mem_endness, disable_actions=True, inspect=False)
    

    def construct_to_set_reg(self, name, register, action_n, hook_addr, bv, eenter, eexit, state: SimState):
        if state.addr == hook_addr or eenter or eexit:
            action_name = f"action_n_{name}"
            if not action_name in state.globals:
                state.globals[action_name] = 1
            else:
                state.globals[action_name] += 1

            if state.globals[action_name] != action_n:
                return

            logger.info(f"Going to set {name} {state}")

            # TODO: keep annotations
            state.regs.__setattr__(register, bv)
        

    def callback_wrapper(self, func, eenter, eexit, state: SimState):
        func(eenter, eexit, state)


    def callback_eexit(self, state: SimState):
        logger.info(f"GOING TO CONCRETIZE EVERYTHINGGG AFTER EEXIT {state}")
        for name, (data_format, type) in state.globals['to_concretize'].items():
            if type == 0:
                real_value = data_format
            elif type == 1: 
                real_value = state.solver.eval(state.memory.load(data_format[0], data_format[1], endness=self.mem_endness, disable_actions=True, inspect=False))
            elif type == 2:
                real_value = state.solver.eval(data_format)
            logger.info(f"Concretizing {name} into {hex(real_value)}")
