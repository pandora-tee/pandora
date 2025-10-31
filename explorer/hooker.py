from __future__ import annotations

import logging
import re

from angr import SimProcedure
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

import ui.log_format
from explorer.sancus_hooks import (
    SimAttest,
    SimClix,
    SimDecrypt,
    SimEncrypt,
    SimGetCallerID,
    SimGetID,
    SimProtect,
    SimUnprotect,
)
from explorer.x86 import (
    Rdrand,
    SimAbort,
    SimEnclu,
    SimFxrstor,
    SimFxsave,
    SimLdmxcsr,
    SimMemcmp,
    SimMemcpy,
    SimMemset,
    SimRep,
    SimRet,
    SimVzeroall,
)
from sdks.SymbolManager import SymbolManager

logger = logging.getLogger(__name__)


class SimNop(SimProcedure):
    IS_FUNCTION = False
    NEEDS_ENDBR = False

    def run(self, opstr="", bytes_to_skip=3, mnemonic="", **kwargs):
        logger.info(f"skipping over {bytes_to_skip}-byte instruction {ui.log_format.format_inline_header(f'{mnemonic} {opstr}')} at {self.state.addr:#x}")
        self.state.globals["prev_skipped_inst"] = {"opcode": mnemonic, "addr": self.state.addr, "len": bytes_to_skip, "opstr": opstr}

        self.jump(self.state.addr + bytes_to_skip)


class AbstractHooker:
    def __init__(self, init_state):
        self.init_state = init_state
        self.project = init_state.project

    def hook_mem_region(self, addr, size):
        raise NotImplementedError


class SancusHooker(AbstractHooker):
    instruction_hooks = {
        "0x1380": SimUnprotect,
        "0x1381": SimProtect,
        "0x1382": SimAttest,
        "0x1384": SimEncrypt,
        "0x1385": SimDecrypt,
        "0x1386": SimGetID,
        "0x1387": SimGetCallerID,
        "0x1388": SimNop,
        "0x1389": SimClix,
    }

    def hook_mem_region(self, addr, size):
        SANCUS_INSTR_SIZE = 2
        entry_sym = SymbolManager().get_symbol_exact(addr)
        if entry_sym and re.search(r"__sm_(\w+)_entry|__sm_(\w+)_public_start", entry_sym):
            logger.debug(f"Hooking enclave section [{addr:#x},{addr + size:#x}] ({entry_sym})")
            disasm = SymbolManager().get_objdump(addr, addr + size, arch="msp430")

            for addr, opcode in self.get_sancus_instr_addresses(disasm.splitlines()):
                if opcode in self.instruction_hooks.keys():
                    sim_proc = self.instruction_hooks[opcode](opstr="", bytes_to_skip=2, mnemonic=opcode)
                    tab_str = f"{addr}:\t{opcode:<10}\t{sim_proc.__class__.__name__:<20}\t{str(SANCUS_INSTR_SIZE):<3}"
                    logger.debug(tab_str)
                    self.project.hook(int(addr, 16), hook=sim_proc, length=SANCUS_INSTR_SIZE)
                else:
                    logger.warning(f'Not hooking unrecognized instruction ".word {opcode}" @{addr}')
        else:
            logger.debug(f"Skipping non-enclave section [{addr:#x},{addr + size:#x}] ({entry_sym})")

    """
    Return a list with (address-opcode) pairs of all Sancus related instructions
    @param section: [String]
        a list of strings containing the objdump of the project
    @return [(address, opcode)]
        a list with address opcode pairs
    """

    def get_sancus_instr_addresses(self, section):
        instructions = []
        # Regex for following kind of line:
        #    6ca4:       86 13           .word   0x1386
        # where the address and the opcode (0x1386) get captured
        regex = re.compile(r"^\s{4}([0-9A-Fa-f]+).*\.word\s*(0x[0-9A-Fa-f]+)")
        for instr in section:
            if ".word" in instr:
                match = regex.match(instr)
                addr = match.group(1)
                op = match.group(2)
                instructions.append(("0x" + str(addr), op))
        return instructions


class SGXHooker(AbstractHooker):
    """
    This class manages the hooking of instructions. It is loosely based on Guardian's class of the same name.
    """

    fct_map = {
        "memcpy": SimMemcpy,
        "memset": SimMemset,
        "memcmp": SimMemcmp,
        # TODO hack to skip the time ocall in Zircon pal_linux_main
        "_DkSystemTimeQuery": SimRet,
        # TODO hack to skip zircon mbedtls init (angr errors with something like unsupported dirty helper amd64 aeskeygen)
        "PalCryptoInit": SimRet,
        # TODO hack to skip unsupported aes instructions in DCAP PLE
        "aesni_setkey_enc_128": SimRet,
        "mbedtls_aesni_crypt_ecb": SimRet,
    }
    fct_addr_map = {}

    def __init__(self, init_state):
        super().__init__(init_state)
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.skipdata = True

        for f, proc in self.fct_map.items():
            addr = self.hook_fct_addr(f)
            if addr:
                self.fct_addr_map[addr] = (f, proc())

    def hook_fct_addr(self, name):
        addr = SymbolManager().symbol_to_addr(name)
        if addr is not None:
            logger.debug(ui.log_format.format_fields(f"hooking function <{name}> at {addr:#x}"))
            logger.debug(ui.log_format.format_asm(self.init_state, use_ip=addr))
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
            fct = ""
            if i.address in self.fct_addr_map.keys():
                fct, sim_proc = self.fct_addr_map[i.address]
            if sim_proc is not None:
                tab_str = f"{i.address:#x}:\t{i.mnemonic:<10}\t{i.op_str:<20}\t{i.size:<3}\t{fct}"
                if fct != "" and sim_proc.NEEDS_ENDBR and "endbr" not in i.mnemonic:
                    logger.warning(tab_str + " SKIPPING (no endbr)")
                    continue

                if type(sim_proc) is not SimAbort:
                    logger.debug(tab_str)

                self.project.hook(i.address, hook=sim_proc, length=i.size)

    # Prepare a dict with instruction replacements and their replacement class
    instruction_hooks = {
        "enclu": SimEnclu,
        "xsavec64": SimFxsave,
        "xsave64": SimFxsave,
        "fxsave64": SimFxsave,
        "ldmxcsr": SimLdmxcsr,
        "fxrstor": SimFxrstor,
        "fxrstor64": SimFxrstor,
        "xrstor": SimFxrstor,
        "xrstor64": SimFxrstor,
        "vzeroall": SimVzeroall,
        "rdrand": Rdrand,
        "int3": SimAbort,
        "verw": SimNop,
        # rep is handled by SimRep but is  checked for partial and not complete equality below.
    }

    def instruction_replacement(self, capstone_instruction) -> SimProcedure | None:
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


# XXX this could also be passed via the SDKManager if we get >1 TEE-specific hooker per architecture
HOOKERS = {"x86_64": SGXHooker, "msp430": SancusHooker}


class HookerManager:
    def __init__(self, init_state, exec_ranges=None, live_console=None, task=None, angr_arch="x86_64"):
        self.init_state = init_state
        self.project = init_state.project
        self.exec_ranges = exec_ranges
        self.hooker = HOOKERS[angr_arch](init_state)

        logger.info("Hooking instructions.")
        loop_count = 0
        # Distinguish between ELF and memory dump: sections may be empty
        section_count = len(self.project.loader.main_object.sections)
        logger.debug("Address        \tInstruction\tOpstr               \tSize [Replacement function]")
        if section_count != 0:
            # Normal elf file, pick executable sections and start hooking
            if live_console:
                live_console.update(task, total=section_count, completed=0)
            for section in self.project.loader.main_object.sections:
                # note: skip NOBITS sections that are uninitialized
                if section.is_executable and not section.only_contains_uninitialized_data:
                    self.hooker.hook_mem_region(section.vaddr, section.memsize)
                loop_count += 1
                live_console.update(task, completed=loop_count)
        else:
            # Not a normal elf file. In this case, utilize the code pages we got
            if not exec_ranges:
                logger.error(ui.log_format.format_error("Can't hook without a memory layout yet!"))
                exit(1)

            total_count = len(self.exec_ranges)
            if live_console:
                live_console.update(task, total=total_count, completed=0)
            for offset, count in self.exec_ranges:
                self.hooker.hook_mem_region(offset, count)
                loop_count += 1
                live_console.update(task, completed=loop_count)
        logger.info("Hooking instructions completed.")
