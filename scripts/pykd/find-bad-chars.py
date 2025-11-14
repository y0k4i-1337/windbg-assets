import argparse

import pykd


def str_to_int(string):
    return int(string, 16)


def hex_byte(byte_str):
    """validate user input is a hex representation of an int between 0 and 255 inclusive"""
    if byte_str == "??":
        # windbg shows ?? when it can't access a memory region, but we shouldn't stop execution because of it
        return byte_str

    try:
        val = int(byte_str, 16)
        if 0 <= val <= 255:
            return val
        else:
            raise ValueError
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"only *hex* bytes between 00 and ff are valid, found {byte_str}"
        )


class BadCharFinder:

    def __init__(self, addr, start, end, bad):
        try:
            self.addr = pykd.expr(addr)
        except:
            self.addr = int(addr, 16)
        self.start = start
        self.end = end
        self.bad = bad
        self.new_bad = list()
        self.expected = list()
        self.results = list()

    def create_expected(self):
        self.expected = [
            i for i in range(self.start, self.end + 1) if i not in self.bad
        ]

    def compare(self):
        prev_bad = False
        for i in range(len(self.expected)):
            mem = pykd.loadBytes(self.addr + i, 1)[0]
            if mem == self.expected[i]:
                prev_bad = False
                continue
            if not prev_bad:
                self.new_bad.append(self.expected[i])
                prev_bad = True
                continue
            print(
                "[+] Consecutive bad chars (data possibly truncated), aborting..."
            )
            break

    def find(self):
        self.create_expected()
        self.compare()

    def __str__(self):
        if not self.new_bad:
            return "[+] No bad characters found"
        else:
            chars = ",".join(["0x{:02x}".format(x) for x in self.new_bad])
            return "[+] Bad chars: {}".format(chars) + "\n"


def find_bad_chars(args):

    finder = BadCharFinder(args.address, args.start, args.end, args.bad)
    finder.find()
    print(finder)


def generate_byte_string(args):
    known_bad = ", ".join(f"{x:02x}" for x in args.bad)
    var_str = f"chars = bytes(i for i in range({args.start}, {args.end + 1}) if i not in [{known_bad}])"

    print("[+] characters as a range of bytes")
    print(var_str, end="\n\n")

    print("[+] characters as a byte string")

    # deliberately not using enumerate since it may not execute in certain situations depending on user input for the
    # range bounds
    counter = args.start
    emptyLine = True

    print("badchars  = b'", end="")

    for i in range(args.start, args.end + 1):
        if counter % 16 == 0 and not emptyLine:
            # start a new line
            print("'")
            print("badchars += b'", end="")
            emptyLine = True

        counter += 1

        if i in args.bad:
            continue
        else:
            print(f"\\x{i:02x}", end="")
            emptyLine = False

    if counter != 0 and not emptyLine:
        print("'")


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-s",
        "--start",
        help="first byte in range to search (default: 00)",
        default="00",
        type=hex_byte,
    )
    parser.add_argument(
        "-e",
        "--end",
        help="last byte in range to search (default: ff)",
        default="ff",
        type=hex_byte,
    )
    parser.add_argument(
        "-b",
        "--bad",
        help="known bad characters (eg: `-b 00 0a 0d`)",
        default=[],
        nargs="+",
        type=hex_byte,
    )
    mutuals = parser.add_mutually_exclusive_group(required=True)
    mutuals.add_argument(
        "-a",
        "--address",
        help="address from which to begin character comparison",
    )
    mutuals.add_argument(
        "-g",
        "--generate",
        help="generate a byte string suitable for use in source code",
        action="store_true",
    )
    args = parser.parse_args()

    if args.start > args.end:
        print("[-] Start byte cannot be greater than end byte")
        return

    if args.address is not None:
        find_bad_chars(args)
    else:
        generate_byte_string(args)


if __name__ == "__main__":
    main()
