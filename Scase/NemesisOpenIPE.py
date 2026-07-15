import logging

import angr
import angr_platforms.msp430.instrs_msp430 as msp430_instrs
import angr_platforms.msp430.arch_msp430 as msp430_arch
import angr_platforms.msp430.lift_msp430 as msp430_lifter
import csv
import pyvex.stmt as stm

from functools import partial
from .BasicScase import BaseScase


logger = logging.getLogger(__name__)

name = "NemesisOpenIPE"


class NemesisOpenIPE(BaseScase):
    # Here the offset represents how much instructions we're supposed to let before running 
    def __init__(self, cftrace, dftrace, shortname=''):
        super().__init__(cftrace, dftrace, shortname)

        self.cftrace = self.parse_csv(self.cftrace_file)


    @staticmethod
    def get_help_text():
        return (
            "This SCASE plugin is pruning states according to a control-flow given by NEMESIS attack." \
            "Note: The trace should be a list of cycles (we can put -1 to ignore an instruction)"
        )

    @staticmethod
    def supports_arch(angr_arch):
        return angr_arch == "msp430"
    

    @staticmethod
    def need_dftrace():
        return False


    @staticmethod
    def parse_csv(trace):
        with open(trace) as trfile:
            data = csv.reader(trfile)
            return list(map(int, list(data)[0]))
        

    # introduce a penalty if the destination is in the ROM
    # We're supposed to be in IPE so when we write into memory it's always in the ROM
    @staticmethod
    def rom_penalty(instruction_parsed):
        if isinstance(instruction_parsed, msp430_instrs.Instruction_CMP) or isinstance(instruction_parsed, msp430_instrs.Instruction_BIT):
            return 0
        return 1
    

    @staticmethod
    def get_src_real_mode(src_bits, mode_bits):
        src = msp430_arch.ArchMSP430.register_index[int(src_bits, 2)]
        src_mode = int(mode_bits, 2)

        # Symbolic and Immediate modes use the PC as the source.
        if src == 'pc':
            if src_mode == msp430_arch.ArchMSP430.Mode.INDEXED_MODE:
                src_mode = msp430_arch.ArchMSP430.Mode.SYMBOLIC_MODE
            elif src_mode == msp430_arch.ArchMSP430.Mode.INDIRECT_AUTOINCREMENT_MODE:
                src_mode = msp430_arch.ArchMSP430.Mode.IMMEDIATE_MODE
        # Resolve the constant generator stuff.
        elif src == 'cg':
            if src_mode == msp430_arch.ArchMSP430.Mode.REGISTER_MODE:
                src_mode = msp430_arch.ArchMSP430.Mode.CONSTANT_MODE0
            elif src_mode == msp430_arch.ArchMSP430.Mode.INDEXED_MODE:
                src_mode = msp430_arch.ArchMSP430.Mode.CONSTANT_MODE1
            elif src_mode == msp430_arch.ArchMSP430.Mode.INDIRECT_REGISTER_MODE:
                src_mode = msp430_arch.ArchMSP430.Mode.CONSTANT_MODE2
            else:
                src_mode = msp430_arch.ArchMSP430.Mode.CONSTANT_MODE_NEG1
        # If you use the SR as the source. things get weird.
        elif src == 'sr':
            if src_mode == msp430_arch.ArchMSP430.Mode.INDEXED_MODE:
                src_mode = msp430_arch.ArchMSP430.Mode.ABSOLUTE_MODE
            elif src_mode == msp430_arch.ArchMSP430.Mode.INDIRECT_REGISTER_MODE:
                src_mode = msp430_arch.ArchMSP430.Mode.CONSTANT_MODE4
            elif src_mode == msp430_arch.ArchMSP430.Mode.INDIRECT_AUTOINCREMENT_MODE:
                src_mode = msp430_arch.ArchMSP430.Mode.CONSTANT_MODE8

        return src_mode
    

    @staticmethod
    def get_dst_real_mode(dst_bits, mode_bits):
        dst = msp430_arch.ArchMSP430.register_index[int(dst_bits, 2)]
        dst_mode = int(mode_bits, 2)

        # Using sr as the dst enables "absolute addressing"
        if dst == 'sr' and dst_mode == msp430_arch.ArchMSP430.Mode.INDEXED_MODE:
            dst_mode = msp430_arch.ArchMSP430.Mode.ABSOLUTE_MODE

        return dst_mode

    def get_instruction_length(self, instruction_parsed, instruction_length) -> set[int]:
        if isinstance(instruction_parsed, msp430_instrs.Type1Instruction):
            logger.debug("Instruction is of format 2")

            if isinstance(instruction_parsed, msp430_instrs.Instruction_RETI):
                return {5}

            As = self.get_src_real_mode(instruction_parsed.data['s'], instruction_parsed.data['A'])    
            match As:
                case msp430_arch.ArchMSP430.Mode.REGISTER_MODE | msp430_arch.ArchMSP430.Mode.CONSTANT_MODE0 | msp430_arch.ArchMSP430.Mode.CONSTANT_MODE1 | msp430_arch.ArchMSP430.Mode.CONSTANT_MODE2 | msp430_arch.ArchMSP430.Mode.CONSTANT_MODE4 | msp430_arch.ArchMSP430.Mode.CONSTANT_MODE8 | msp430_arch.ArchMSP430.Mode.CONSTANT_MODE_NEG1:
                    if isinstance(instruction_parsed, msp430_instrs.Instruction_PUSH):
                        return {3, 3 + self.rom_penalty(instruction_parsed)}
                    elif isinstance(instruction_parsed, msp430_instrs.Instruction_CALL):
                        # 4 on MSP430
                        return {3, 3 + self.rom_penalty(instruction_parsed)}
                    else:
                        return {1}

                case msp430_arch.ArchMSP430.Mode.INDEXED_MODE | msp430_arch.ArchMSP430.Mode.SYMBOLIC_MODE | msp430_arch.ArchMSP430.Mode.ABSOLUTE_MODE:
                    if isinstance(instruction_parsed, msp430_instrs.Instruction_PUSH):
                        return {5, 5 + self.rom_penalty(instruction_parsed)}
                    elif isinstance(instruction_parsed, msp430_instrs.Instruction_CALL):
                        return {5, 5 + self.rom_penalty(instruction_parsed)}
                    else:
                        return {4, 4 + self.rom_penalty(instruction_parsed)}
                case msp430_arch.ArchMSP430.Mode.INDIRECT_REGISTER_MODE:
                    if isinstance(instruction_parsed, msp430_instrs.Instruction_PUSH):
                        return {4, 4 + self.rom_penalty(instruction_parsed)}
                    elif isinstance(instruction_parsed, msp430_instrs.Instruction_CALL):
                        return {4, 4 + self.rom_penalty(instruction_parsed)}
                    else:
                        return {3, 3 + self.rom_penalty(instruction_parsed)}
                case msp430_arch.ArchMSP430.Mode.INDIRECT_AUTOINCREMENT_MODE:
                    if isinstance(instruction_parsed, msp430_instrs.Instruction_PUSH):
                        # 5 on MSP430
                        return {4, 4 + self.rom_penalty(instruction_parsed)}
                    elif isinstance(instruction_parsed, msp430_instrs.Instruction_CALL):
                        # 5 on MSP430
                        return {4, 4 + self.rom_penalty(instruction_parsed)}
                    else:
                        return {3, 3 + self.rom_penalty(instruction_parsed)}
                case msp430_arch.ArchMSP430.Mode.IMMEDIATE_MODE:
                    if isinstance(instruction_parsed, msp430_instrs.Instruction_PUSH):
                        return {4, 4 + self.rom_penalty(instruction_parsed)}
                    elif isinstance(instruction_parsed, msp430_instrs.Instruction_CALL):
                        return {4, 4 + self.rom_penalty(instruction_parsed)}
            return {0}
        
        elif isinstance(instruction_parsed, msp430_instrs.Type2Instruction):
            logger.debug("Instruction is of format 3")
            return {2}
        
        elif isinstance(instruction_parsed, msp430_instrs.Type3Instruction):
            logger.debug("Instruction is of format 1")
            
            As = self.get_src_real_mode(instruction_parsed.data['s'], instruction_parsed.data['A'])
            Ad = self.get_src_real_mode(instruction_parsed.data['d'], instruction_parsed.data['a'])
            d = int(instruction_parsed.data['d'], 2)

            dadd_penalty = 1 if isinstance(instruction_parsed, msp430_instrs.Instruction_DADD) else 0
            match As:
                case msp430_arch.ArchMSP430.Mode.REGISTER_MODE | msp430_arch.ArchMSP430.Mode.CONSTANT_MODE0 | msp430_arch.ArchMSP430.Mode.CONSTANT_MODE1 | msp430_arch.ArchMSP430.Mode.CONSTANT_MODE2 | msp430_arch.ArchMSP430.Mode.CONSTANT_MODE4 | msp430_arch.ArchMSP430.Mode.CONSTANT_MODE8 | msp430_arch.ArchMSP430.Mode.CONSTANT_MODE_NEG1:
                    if Ad == msp430_arch.ArchMSP430.Mode.REGISTER_MODE or Ad == msp430_arch.ArchMSP430.Mode.CONSTANT_MODE0 or Ad == msp430_arch.ArchMSP430.Mode.CONSTANT_MODE1 or Ad == msp430_arch.ArchMSP430.Mode.CONSTANT_MODE2 or Ad == msp430_arch.ArchMSP430.Mode.CONSTANT_MODE4 or Ad == msp430_arch.ArchMSP430.Mode.CONSTANT_MODE8 or Ad == msp430_arch.ArchMSP430.Mode.CONSTANT_MODE_NEG1:
                        if msp430_arch.ArchMSP430.register_index[d] == 'pc':
                            return {2 + dadd_penalty}
                        return {1 + dadd_penalty}
                    elif Ad == msp430_arch.ArchMSP430.Mode.INDEXED_MODE or Ad == msp430_arch.ArchMSP430.Mode.SYMBOLIC_MODE or Ad == msp430_arch.ArchMSP430.Mode.ABSOLUTE_MODE:
                        return {4 + dadd_penalty, 4 + self.rom_penalty(instruction_parsed) + dadd_penalty}
                case msp430_arch.ArchMSP430.Mode.INDEXED_MODE | msp430_arch.ArchMSP430.Mode.SYMBOLIC_MODE | msp430_arch.ArchMSP430.Mode.ABSOLUTE_MODE:
                    if Ad == msp430_arch.ArchMSP430.Mode.REGISTER_MODE:
                        if msp430_arch.ArchMSP430.register_index[d] == 'pc':
                            return {4 + dadd_penalty}
                        return {3 + dadd_penalty}
                    elif Ad == msp430_arch.ArchMSP430.Mode.INDEXED_MODE or Ad == msp430_arch.ArchMSP430.Mode.SYMBOLIC_MODE or Ad == msp430_arch.ArchMSP430.Mode.ABSOLUTE_MODE:
                        return {6 + dadd_penalty, 6 + self.rom_penalty(instruction_parsed) + dadd_penalty}
                case msp430_arch.ArchMSP430.Mode.INDIRECT_REGISTER_MODE | msp430_arch.ArchMSP430.Mode.INDIRECT_AUTOINCREMENT_MODE |  msp430_arch.ArchMSP430.Mode.IMMEDIATE_MODE:
                    if Ad == msp430_arch.ArchMSP430.Mode.REGISTER_MODE:
                        if msp430_arch.ArchMSP430.register_index[d] == 'pc':
                            return {3 + dadd_penalty}
                        return {2 + dadd_penalty}
                    elif Ad == msp430_arch.ArchMSP430.Mode.INDEXED_MODE or Ad == msp430_arch.ArchMSP430.Mode.SYMBOLIC_MODE or Ad == msp430_arch.ArchMSP430.Mode.ABSOLUTE_MODE:
                        return {5 + dadd_penalty, 5 + self.rom_penalty(instruction_parsed) + dadd_penalty}

        return {-1}


    @staticmethod
    def get_nb_instrs(state: angr.SimState, step_size=None):
        total_instructions = 0   

        for addr in state.history.bbl_addrs:
            block = state.project.factory.block(addr)
            if step_size:
                total_instructions += min(step_size, block.instructions)
            else:
                total_instructions += block.instructions

        return total_instructions


    def should_prune_state(self, step_size, state: angr.SimState):
        # Analysis is made block by block
        if state.addr != state.block().addr:
            return False
        
        index_in_trace = self.get_nb_instrs(state, step_size)

        for instr in state.block().vex.statements: 
            if not isinstance(instr, stm.IMark):
                continue

            instr_adrr = instr.addr
            instr_size = instr.len
            try:
                instr_opcode = int(state.memory.load(instr_adrr, instr_size).concrete_value)
            except TypeError:
                logger.warning(f"{state}'s memory can't be converted to int!")
                continue


            logger.debug(f"Instruction is at adress {hex(instr_adrr)} and of size {instr_size} and opcode {hex(instr_opcode)}")
            lifter = msp430_lifter.LifterMSP430(state.block().arch, instr_adrr)

            lifter.lift(instr_opcode.to_bytes(instr_size, 'big'), max_inst=1, disasm=True)

            if index_in_trace < len(self.cftrace) and self.cftrace[index_in_trace] != -1:
                instr_parsed = lifter.decode()[0]
                instr_parsed.disassemble()

                nb_true = self.get_instruction_length(instr_parsed, instr_size // 2)

                logger.debug(f"Number of cycles for {lifter.disassembly}: {nb_true}")
                logger.debug(f"Supposed number of cycles according to trace {self.cftrace[index_in_trace]}")
                
                if self.cftrace[index_in_trace] not in nb_true:
                    logger.info(f"Dropping state {state}")
                    return True

            index_in_trace += 1
        return False
        

    def prune_states(self, step_size, simgr: angr.SimulationManager):
        wrapper = partial(
            self.should_prune_state,
            step_size
        )
        simgr.move(from_stash='active', to_stash='deadended', filter_func=wrapper)
