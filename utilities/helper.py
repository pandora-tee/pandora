import json
import logging


def file_stream_is_elf_file(stream):
    """
    Checks whether a file stream currently has a legit elf file open.
    Verifies that the ELF HEADER exists.
    """
    stream.seek(0)
    elf_magic = stream.read(4)
    stream.seek(0)
    if elf_magic == b'\x7fELF':
        return True
    else:
        return False

def decode_as_json(json_path):
    """
    Takes a path to a json file and returns an object loaded by the json library.
    """
    logger = logging.getLogger()

    with open(json_path, 'r') as f:
        try:
            json_dict = json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f'Json Decode error on file {json_path}:\n{str(e)}')
            exit(1)
    return json_dict
