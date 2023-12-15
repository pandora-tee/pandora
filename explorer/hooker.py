from __future__ import annotations

import angr
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

import ui.log_format
from explorer.x86 import SimEnclu, Rdrand, SimFxrstor, SimRep, SimVzeroall, SimFxsave, SimMemcpy, SimMemcmp, SimMemset, SimRet, SimAbort, SimLdmxcsr, SimNop
from sdks.SymbolManager import SymbolManager

import logging

logger = logging.getLogger(__name__)


class HookerManager:
    """
    This class manages the hooking of instructions. It is loosely based on Guardian's class of the same name.
    """

    fct_map = { 'memcpy'                  : SimMemcpy,
                'memset'                  : SimMemset,
                'memcmp'                  : SimMemcmp,
                #TODO hack to skip the time ocall in Zircon pal_linux_main
                '_DkSystemTimeQuery'      : SimRet,
                #TODO hack to skip zircon mbedtls init (angr errors with something like unsupported dirty helper amd64 aeskeygen)
                'PalCryptoInit'           : SimRet,
                #TODO hack to skip unsupported aes instructions in DCAP PLE
                'aesni_setkey_enc_128'    : SimRet,
                'mbedtls_aesni_crypt_ecb' : SimRet,
              }
    fct_addr_map = {}
    sim_abort_count = 0

    def __init__(self, init_state, code_pages = None, live_console=None, task=None):
        self.init_state = init_state
        self.project = init_state.project
        self.code_pages = code_pages

        logger.info("Hooking instructions.")

        for f, proc in self.fct_map.items():
            addr = self.hook_fct_addr(f)
            if addr:
                self.fct_addr_map[addr] = (f, proc())

        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.skipdata = True

        loop_count = 0
        # Distinguish between elf loading and dump loading: sections may be empty
        section_count = len(self.project.loader.main_object.sections)
        logger.debug(f'Address        \tInstruction\tOpstr               \tSize [Replacement function]')
        if section_count != 0:
            # Normal elf file, pick executable sections and start hooking
            if live_console:
                live_console.update(task, total=section_count, completed=0)
            for section in self.project.loader.main_object.sections:
                # note: skip NOBITS sections that are uninitialized
                if section.is_executable and not section.only_contains_uninitialized_data:
                    self.hook_mem_region(section.vaddr, section.memsize)
                loop_count += 1
                live_console.update(task, completed=loop_count)
        else:
            # Not a normal elf file. In this case, utilize the code pages we got
            if not code_pages:
                logger.error(ui.log_format.format_error(f"Can't hook without a memory layout yet!"))
                exit(1)

            total_count = len(self.code_pages)
            if live_console:
                live_console.update(task, total=total_count, completed=0)
            for (offset, count) in self.code_pages:
                self.hook_mem_region(offset, count)
                loop_count += 1
                live_console.update(task, completed=loop_count)

            if self.sim_abort_count > 0:
                logger.debug(f'Also hooked {self.sim_abort_count} instructions for abort (ud2, int3 etc).')

        logger.info("Hooking instructions completed.")

    def hook_fct_addr(self, name):
        addr = SymbolManager().symbol_to_addr(name)
        if addr is not None:
            logger.debug(ui.log_format.format_fields(f'hooking function <{name}> at {addr:#x}'))
            logger.debug(ui.log_format.format_asm(self.init_state, use_rip=addr))
        return addr

    def hook_mem_region(self, addr, size):
        """
        Hooks a whole memory region at once with SimProcedures.
        :param addr: Address to start hooking at
        :param size: Size of the region
        """

        section_bytes = self.project.loader.memory.load(addr, size)

        for i in self.md.disasm(section_bytes, addr):
            sim_proc = self.instruction_replacement(i)
            fct = ''
            if i.address in self.fct_addr_map.keys():
                fct, sim_proc = self.fct_addr_map[i.address]
            if sim_proc is not None:
                tab_str = f'{i.address:#x}:\t{i.mnemonic:<10}\t{i.op_str:<20}\t{i.size:<3}\t{fct}'
                if fct != '' and sim_proc.NEEDS_ENDBR and 'endbr' not in i.mnemonic:
                    logger.warning(tab_str + ' SKIPPING (no endbr)')
                    continue

                if type(sim_proc) is not SimAbort:
                    logger.debug(tab_str)
                else:
                    self.sim_abort_count += 1

                self.project.hook(i.address, hook=sim_proc, length=i.size)



    # Prepare a dict with instruction replacements and their replacement class
    instruction_hooks = {
        'enclu': SimEnclu,

        'xsavec64': SimFxsave,
        'xsave64': SimFxsave,
        'fxsave64': SimFxsave,

        'ldmxcsr': SimLdmxcsr,

        'fxrstor': SimFxrstor,
        'fxrstor64': SimFxrstor,
        'xrstor': SimFxrstor,
        'xrstor64': SimFxrstor,
        'vzeroall': SimVzeroall,
        'rdrand': Rdrand,

        'int3' : SimAbort,

        'verw' : SimNop,

        # rep is handled by SimRep but is  checked for partial and not complete equality below.
    }
    def instruction_replacement(self, capstone_instruction) -> angr.SimProcedure | None:
        """
        Replaces a capstone instruction with a SimProcedure or returns None if no replacement is necessary.
        :param capstone_instruction: Instruction as returned by the disassembler
        :return: A SimProcedure or None
        """
        size = capstone_instruction.size

        mnemonic = capstone_instruction.mnemonic
        # General case: If we have a hook for it, use that.
        if mnemonic in self.instruction_hooks:
            return self.instruction_hooks[mnemonic](opstr=capstone_instruction.op_str, bytes_to_skip=size, mnemonic=mnemonic)
        # Edge case, rep may look differently each time but always starts with rep
        elif capstone_instruction.mnemonic[0:4] == "rep ":
            return SimRep(inst=capstone_instruction)
        # Default case: No replacement
        else:
            return None
