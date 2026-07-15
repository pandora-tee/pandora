# Using script to concretize memory with Pandora

## Basic syntax

```bash
<script>    := (concretize <expr> (alias <name>)? of size <size> when <event>)*
<expr>      := <register> | <memory> | <symbol>

<memory>    := memory((<register> <arbinop>)? <size>)
<symbol>    := symbol(<name>)

<event>     :=  <hook> | eenter | eexit
                              
<hook>      := addr=<size> (n=<size>)? 

<arbinop>   := + | -

```

## Notes

On the syntax shown above `<register>`are architecture dependant so for exemple while using x86-64 use `rsp` but for msp430 use `r1`.

The `<size>` could be written in decimal and hexadecimal (prefixed by `0x`).

If not alias is given then a default (and unique) name will be given to your variable. 

## Exemple on msp430

```bash
concretize r15 alias register_concr of size 16 when addr=0x81bc
```

With this command we want to know the value of the `r15` register before instruction `0x18bc`.

```bash
concretize memory(0x81e0) alias memory_secret of size 16 when addr=0x81bc
```

With this command what's inside memory at adress `0x81e0` register before instruction `0x18bc`.

```bash
concretize symbol(private_key) of size 16 when eenter
```

With this command what's the value of the symbol `private_key` before entering the enclave.
