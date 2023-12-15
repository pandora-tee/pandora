import logging
import bisect
from elftools.elf.elffile import ELFFile

from utilities.Singleton import Singleton
from utilities.helper import file_stream_is_elf_file
import ui

from functools import lru_cache

logger = logging.getLogger(__name__)

# TODO probably should better subclass this w/ and w/o symbol table..
class SymbolManager(metaclass=Singleton):

    def __init__(self, init_state=None, elf_file=None, base_addr=0, sdk_name=''):
        """
        Expects the symbol table to be in the form of
        [(addr, name)]
        """
        if init_state is None:
            logger.error(f'SymbolManager called without init state. Failed setup.')
            exit(1)
        self.init_state = init_state

        if sdk_name == 'Enclave memory dump' and elf_file is None:
            logger.critical(f'Running a dump file without giving the --sdk-elf-file option means that we will not have access to symbols! We suggest to use the --sdk-elf-file option and give an elf file.')

        self._create_symbol_table(elf_file, base_addr)

    def _create_symbol_table(self, elf_file, base_addr):
        """
        Load the optional elf file to gather the symbols and relocate them based to base addr
        """
        if elf_file is None:
            self.symbol_table = None
            return

        self.symbol_table = []
        self.elf_name = str(elf_file)

        elf_stream = open(elf_file, 'rb')
        if not file_stream_is_elf_file(elf_stream):
            logger.error(f'File {elf_file} is not a legit elf file!')
            exit(1)

        symtab = ELFFile(elf_stream).get_section_by_name('.symtab')

        # this is currently a hack: we probably want to specify 
        # the offset when providing an ELF symbol file via the command 
        # line; better seems a config or json to have all this together 
        # instead of individual messy cmd line opts; even better would be 
        # to specify a symbol (e.g., "enclave_entry") that is specified in 
        # the TCS entry point so the offset can be auto calculated :)
        self.rebase_offset = base_addr
        sdk_rebases = {
            'enclaveos' : 0xFE78000, # zircon
            'gramine'   : 0xFE3E000,
            'scone-5.7' : 0xFFFEFF600,
            'scone-5.8' : 0x1000010000, # scone hello_1798.objcopy.in
            'gotee'     : -0x2700,
        }
        for partial_name in sdk_rebases.keys():
            if partial_name in self.elf_name:
                self.rebase_offset = sdk_rebases[partial_name]
                logger.info(f'Identified this as a {partial_name} SDK and enforcing a symbol offset of {self.rebase_offset:#x}')
                break

        for s in symtab.iter_symbols():
            t = s.entry['st_info']['type']
            if t == 'STT_FUNC' or t == 'STT_OBJECT' or t == 'STT_NOTYPE':
                self.symbol_table.append((s.entry['st_value'] + self.rebase_offset, s.name))

        self.symbol_table.sort(key=lambda t: t[0])

        # convert tuple (addr,name) to map(addr:name)
        self.symbol_table = {k:v for (k,v) in self.symbol_table}

        # Keep a list of the symbol table to not convert it on every call
        self.symbol_table_list = list(self.symbol_table)
        self.symbol_table_value_list = list(self.symbol_table.values())

        #logger.debug(f'Parsed these elf symbols to be used:\n{ui.log_format.format_fields(self.symbol_table)}')

    def _bisect_idx(self, addr):
        # use binary search to find symbol closest before given addr
        # https://docs.python.org/3/library/bisect.html
        # NOTE: key argument not supported on python < 3.10, so we convert
        # the tuple list to a map in the constructor
        bisection_index = bisect.bisect(self.symbol_table_list, addr)
        if 0 < bisection_index:
            # We got the index after the one we want to print, correct this
            bisection_index -= 1
        return bisection_index

    @lru_cache(maxsize=256, typed=False)
    def get_symbol(self, addr):
        """
        Takes an addr and resolves it to a symbol name. Either utilizes the angr loader for this
        or if that does not resolve a name (for example when investigating enclave memory dumps), defaults back to
        the enclave layout symbol table given via the ELF file.
        If neither of this is successful, symbols are called UNKNOWN
        """
        if self.symbol_table is None:
            sym = self.init_state.project.loader.find_symbol(addr, fuzzy=True)
            if sym is not None:
                return sym.name
            else:
                return "UNKNOWN"
        else:
            idx = self._bisect_idx(addr)
            return self.symbol_table_value_list[idx]

    def get_symbol_exact(self, addr):
        if self.symbol_table is None:
            sym = self.init_state.project.loader.find_symbol(addr)
            if sym is not None:
                return sym.name
        else:
            if addr in self.symbol_table.keys():
                return self.symbol_table[addr]
        return None

    def symbol_to_addr(self, name):
        if self.symbol_table is None:
            sym = self.init_state.project.loader.find_symbol(name)
            if sym is not None:
                return sym.rebased_addr
        else:
            v = list(self.symbol_table.values())
            k = list(self.symbol_table.keys())
            if name in v:
                return k[v.index(name)]
        return None

    def _get_addr_offset(self, addr):
        if self.symbol_table is None:
            sym_name = self.get_symbol(addr)
            offset = 0x0
        else:
            idx = self._bisect_idx(addr)
            prev_addr = list(self.symbol_table)[idx]
            offset = addr - prev_addr
            sym_name = self.symbol_table[prev_addr]

        return sym_name, offset

    def get_hex_symbol(self, addr):
        """
        Used to augment asm output of blob with our own symbol table. Returns
        the closest symbol + offset if any; returns the hex address if not found.
        """
        if self.symbol_table is None:
            return hex(addr)
        else:
            sym_name, offset = self._get_addr_offset(addr)

            idx = self._bisect_idx(addr)
            prev_addr = list(self.symbol_table)[idx]
            offset = addr - prev_addr

            # best effort: if offset is negative or too large, the symbol is
            # likely not helpful/correct
            if offset < 0 or offset > 0x1000:
                return hex(addr)

            offset_str = f'+{offset:#x}' if offset != 0 else ''
            return f'{addr:#x} <{sym_name}{offset_str}>'

    def get_symbol_with_offset(self, addr):
        """
        returns "0xdeadbeef <closest_symbol+0xoffset>"
        """
        sym_name, offset = self._get_addr_offset(addr)
        offset_str = f'+{offset:#x}' if offset != 0 else ''
        return f'{addr:#x} <{sym_name}{offset_str}>'

    def get_rebased_addr(self, addr):
        if self.symbol_table is None:
            base = self.init_state.project.loader.min_addr
        else:
            base = self.rebase_offset

        return addr - base
