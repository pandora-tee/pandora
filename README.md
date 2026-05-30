# Pandora: Principled Symbolic Validation of Enclave Runtimes

Pandora is a symbolic execution tool designed for *truthful* validation of enclave shielding runtimes across diverse TEE architectures. Built on the fabulous [angr](https://angr.io/) framework, Pandora extends it with enclave-aware semantics such as enclave loading, a powerful symbolic memory model to support enclaves in a shared address space, principled taint tracking, human-readable HTML report generation, and a suite of vulnerability detection plugins.

Originally developed for Intel SGX ([:page_facing_up: IEEE S&P'24 paper](https://vanbulck.net/files/oakland24-pandora.pdf)), Pandora's core infrastructure has since been generalized into a TEE-agnostic base, with support extended to the Sancus ([:page_facing_up: SysTEX'25 paper](https://vanbulck.net/files/systex25-pandora-sancus.pdf)) and openIPE ([:page_facing_up: EuroS&P'25 paper](https://vanbulck.net/files/eurosp25-openipe.pdf)) enclave architectures.

If you use Pandora, please cite: 

```
@inproceedings{alder2024pandora,
  title={Pandora: Principled Symbolic Validation of Intel SGX Enclave Runtimes},
  author={Alder, Fritz and Daniel, Lesly-Ann and Oswald, David and Piessens, Frank and Van Bulck, Jo},
  booktitle={45th IEEE Symposium on Security and Privacy-IEEE S\&P 2024},
  year={2024},
  organization={IEEE}
}
```

## Quickstart

To install and run Pandora in a Python virtual environment:

```bash
# create Python virtual environment
$ python3 -m venv venv && source ./venv/bin/activate

# install dependencies in virtual environment
$ python3 -m pip install -r requirements.txt

# now run pandora
(venv) $ ./pandora.py
```

## Example Usage

```bash
# Good CLI hopefully makes it easy for you to get started
./pandora.py --help

# The run script executes Pandora on an ELF file or a binary
./pandora.py run --help

# Easiest example: clone and compile the standalone Linux selftest enclave
cd ..
git clone https://github.com/pandora-tee/pandora-examples.git
cd pandora-examples/linux-sgx-selftest/
make
cd ../../pandora/

# Now analyze the Linux selftest enclave binary
./pandora.py run ../pandora-examples/linux-sgx-selftest/linux_test_encl.elf

# When you start playing around, start using the debugging config file
# This makes sure to not always write new HTML and json reports, but overwrites old reports
#  --> Less wasted disk space while you hack around
# You can also control color schemes in these config files! This one works well for our dark modes.
./pandora.py run -c config-debugging.ini ../pandora-examples/linux-sgx-selftest/linux_test_encl.elf

# More tricky example: An sgx-tracer dump, by giving the -s dump option:
./pandora.py run -c config-debugging.ini ../pandora-examples/intel-sdk/bin-and-sgxtrace/sgx_2.19.enclave.dump -s dump

# Pandora is usually smart enough to also detect the *.json and *.so files of the same name. If not, pass them explicitly
# Pandora needs the JSON for metadata of the dump, and if the elf file exists, can re-use its symbols to generate a backtrace
./pandora.py run -c config-debugging.ini ../pandora-examples/intel-sdk/bin-and-sgxtrace/sgx_2.19.enclave.dump -s dump --sdk-json-file=../pandora-examples/intel-sdk/bin-and-sgxtrace/sgx_2.19.enclave.json --sdk-elf-file=../pandora-examples/intel-sdk/bin-and-sgxtrace/sgx_2.19.enclave.so

# You can also control Pandora's behavior
# Only do 20 steps:
./pandora.py run -c config-debugging.ini ../pandora-examples/linux-sgx-selftest/linux_test_encl.elf -n 20

# Wait for user input before starting (e.g. to verify everything is loaded correctly)
./pandora.py run -c config-debugging.ini ../pandora-examples/linux-sgx-selftest/linux_test_encl.elf -a start=break

# Spawn a shell on every pointer sanitization issue
./pandora.py run -c config-debugging.ini ../pandora-examples/linux-sgx-selftest/linux_test_encl.elf -a ptr=shell

# There are more options that can be set like depth-first search and allowing enclave reentries. Check the help how to do that.
```

<!-- 
To get started quickly, we provide a Docker container:

```bash
# Load the Docker container pandora:artifact
docker load < ./pandora.docker

# Enter this Docker container and mount the folder
docker run -it -v ./:/pandora pandora:artifact

``` -->



## Common Pandora errors

Pandora is a research prototype. There are still several types of errors that can occur during an execution of Pandora. Common Pandora errors can look as follows:

```
# Machine runs out of memory:
Program terminated by signal SIGKILL (Forced quit)

# Very Rarely, Z3 crashes occur with one of these:
Segmentation fault (core dumped)
Program terminated by signal SIGSEGV (Address boundary error)
```

In rare cases, Pandora experiences segmentation faults or Z3 issues due to instability between angr and the underlying Z3 solver. We believe that these are issues both in the Python package of `z3-solver` and claripy. 

For us, these issues occur very rarely, and happen non-deterministically. Often, re-running the same binary right away avoids a crash. On some machines, these errors seem to happen more often than on others, and for those machines, we had success in updating the Z3 Python package: `pip install --upgrade z3-solver`.

## Updating dependencies

To generate an updated `requirements.txt` from within the virtual environment:

```bash
$ ./venv/bin/pip list --outdated
$ ./venv/bin/pip install pip-review
$ ./venv/bin/pip-review --auto
$ ./venv/bin/pip freeze > requirements.txt
```

## Source code overview

Directory structure is organized as follows:

```
.
- assets      -- Collection of static data for the HTML report generation.
- explorer    -- Symbolic execution machinery: exploration strategies and
                 angr hooks for implementing missing x86 semantics.
- pithos      -- Python classes to implement the actual validation logic for
                 detecting different vulnerabilities using angr and pandora breakpoints.
- sdks        -- Python classes to abstract binary specifics for different
                 SGX shielding runtimes.
- tests       -- Python methods to perform pandora selftests (sanity checks)
- ui          -- User interaction abstracting user input, logging output, and
                 vulnerability report creation.
- utilities   -- Common Pandora and angr functions and helpers
```
