import sys

from darkmach.bridge.client import send_command
from darkmach.bridge.render import format_response
from darkmach.bridge.shell import interactive_mode, parse_cli_args

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd, args = parse_cli_args(sys.argv[1:])
        r = send_command(cmd, args)
        print(format_response(r, cmd))
    else:
        interactive_mode()
