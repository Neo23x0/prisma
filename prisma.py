#!/usr/bin/env python3
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-

"""
Prisma

Automatic Command Line Colorizer
by Florian Roth
"""
__version__ = '0.4'

import sys
import argparse
import re
import traceback
import time
from colorama import Fore, Back, Style
from colorama import init


class Prisma():

    debug_mode = False

    # Generic colorisation
    generic_colorisation = True

    # Highlight Strings
    string_match_caseinsensitive = False
    wait_time = 0
    highlight_strings = []
    string_highlight = Fore.WHITE+Back.RED+Style.BRIGHT

    # Predefined colors
    base_color = Fore.WHITE+Back.BLACK+Style.NORMAL

    cyan_highlight = Fore.CYAN+Back.BLACK+Style.BRIGHT
    green_highlight = Fore.GREEN+Back.BLACK+Style.BRIGHT
    yellow_highlight = Fore.YELLOW+Back.BLACK+Style.BRIGHT
    magenta_highlight = Fore.MAGENTA+Back.BLACK+Style.BRIGHT
    blue_highlight = Fore.BLUE+Back.BLACK+Style.BRIGHT

    cyan_back = Fore.BLACK+Back.CYAN
    green_back = Fore.WHITE+Back.GREEN
    magenta_back = Fore.WHITE+Back.MAGENTA
    blue_back = Fore.WHITE+Back.BLUE

    red = Fore.RED+Back.BLACK
    yellow = Fore.YELLOW+Back.BLACK
    green = Fore.GREEN+Back.BLACK
    magenta = Fore.MAGENTA+Back.BLACK
    blue = Fore.BLUE+Back.BLACK
    grey = Fore.BLACK+Back.BLACK+Style.BRIGHT

    # Dynamic color allocation
    assigned_colors = {}
    FORE_COLORS = {'black': Fore.BLACK, 'red': Fore.RED, 'green': Fore.GREEN, 'blue': Fore.BLUE, 
                   'yellow': Fore.YELLOW, 'mangenta': Fore.MAGENTA, 'cyan': Fore.CYAN, 'white': Fore.WHITE}
    BACK_COLORS = {'black': Back.BLACK, 'red': Back.RED, 'green': Back.GREEN, 'blue': Back.BLUE, 
                   'yellow': Back.YELLOW, 'mangenta': Back.MAGENTA, 'cyan': Back.CYAN, 'white': Back.WHITE}
    # Use this regex instead of IP detection
    dynamic_color_regex = None
    dynamic_color_mode = "IP" # is default or "REGEX"

    # Application
    COLORIZER = [
                # General
                {'name': 'uppercase_keywords', 'regex': r'\b([A-Z]{3,})\b', 'color': cyan_highlight},
                {'name': 'keys_logline', 'regex': r'([A-Z_]{2,}:[\s\t])', 'color': cyan_highlight},
                {'name': 'service', 'regex': r'(\b[A-Za-z]+\[[0-9]+\]:)', 'color': blue_back},
                {'name': 'string', 'regex': r'(\'[^\']+\')', 'color': yellow},
                {'name': 'id_num', 'regex': r'(\[[0-9]+\])', 'color': green},
                {'name': 'id_alpha', 'regex': r'(\[[a-zA-Z\-]+\])', 'color': green_highlight},
                {'name': 'tag', 'regex': r'(<[a-zA-Z_]+>)', 'color': green_back},
                {'name': 'key', 'regex': r'\b(["]?[a-zA-Z]{2,}[a-zA-Z0-9_]+["]?[\s]?[=:])([\s\w\t])',
                 'color': blue_highlight},

                # Specific
                {'name': 'exclamation', 'regex': r'((?![0-9]{2}m) [A-Za-z0-9\-\s\']+!)$', 'color': red},
                {'name': 'date1', 'regex': r'\b([A-Z][a-z][a-z][\s]?[\s][0-9]{1,2}[\s][0-9:]+)(\s[0-9]{4}|)\b',
                 'color': green_back, 'mode': 'mark_all'},
                {'name': 'date2', 'regex': r'\b([0-9]{2}/[0-9]{2}[\s][0-9:]+)\b',
                 'color': green_back},
                {'name': 'IP', 'regex': r'([1-2]?[0-9]?[0-9]\.[1-2]?[0-9]?[0-9]\.[1-2]?[0-9]?[0-9]\.[1-2]?[0-9]?[0-9])',
                 'color': yellow },
                {'name': 'IP', 'regex': r'\b([a-f0-9]{4}:[a-f0-9:\.]+)\b', 'color': yellow },
                {'name': 'env_var_windows', 'regex': r'(%[A-Z_]+%)', 'color': yellow_highlight },
                {'name': 'env_var_linux', 'regex': r'\b($[A-Z_])\b', 'color': yellow_highlight },
                {'name': 'var', 'regex': r'([A-Z]+_[A-Z]+)', 'color': blue },
                {'name': 'success', 'regex': r'([Ss]ucce[a-z]+)\b', 'color': green},
                {'name': 'failure', 'regex': r'([Ff]ail[a-z]+)\b', 'color': red},
                {'name': 'success', 'regex': r'([Aa]ccept[a-z]+|Permit[a-z]+)\b', 'color': green},
                {'name': 'denied', 'regex': r'([Dd]enied|[Dd]eny)\b', 'color': red},
                {'name': 'rejected', 'regex': r'([Rr]ejected)\b', 'color': red},
                {'name': 'warning', 'regex': r'\b([Ww]arn[a-z]*|[Aa]larm[a-z]*|[Aa]lert[a-z]*|[Aa]lert[a-z]*|'
                                             r'[Cc]ritical[a-z]*|[Aa]ttack[a-z]*|[Ii]nject[a-z]*|[Ss]poof[a-z]*|'
                                             r'[Dd]estruct[a-z]*|Could not [^\.]+)\b', 'color': red},
                {'name': 'suspicious', 'regex': r'\b([Aa]ttempt[a-z]*|[Pp]ermiss[a-z]*|[Uu]nauthent[a-z]*|'
                                                r'[Uu]nauthoriz[a-z]*|[Uu]nexpect[a-z]*|[Ss]uspiciou[a-z]*|'
                                                r'[Ll]ockout|[Ll]ocked out|[Ee]ras[a-z]*[Ii]nfect[a-z]*|'
                                                r'[Tt]oo [a-z]+|[Ii]nvalid[a-z]*)\b', 'color': yellow_highlight},
                {'name': 'granted', 'regex': r'([Gg]ranted)\b', 'color': green},
                {'name': 'blocked', 'regex': r'([Bb]locked)\b', 'color': red},
                {'name': 'filepath_linux', 'regex': r'(/[^\s]+/[^\s]+)\b', 'color': green},
                {'name': 'filepath_windows', 'regex': r'([C-Z]:\\[^\s]+)\b', 'color': green},
                {'name': 'zeros', 'regex': r'\b(0000|\\x00)\b', 'color': grey},
                {'name': 'MZ_header', 'regex': r'\b(4d5a\b|4D5A\b|MZ\.\.)', 'color': blue},
                {'name': 'PE_header', 'regex': r'(\b5045\b|\.\.PE\.\.)', 'color': blue},
                {'name': 'bits_bytes', 'regex': r'([0-9]+ bits|[0-9]+ bytes)', 'color': green_highlight},
                {'name': 'hashes', 'regex': r'\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b',
                 'color': yellow_highlight},
                {'name': 'uid', 'regex': r'\b([a-fA-F0-9]{4,16}\-[a-fA-F0-9]{4,16}\-[a-fA-F0-9]{4,16}\-'
                                         r'[a-fA-F0-9]{4,16}\-[a-fA-F0-9]{4,20})\b', 'color': yellow},
                {'name': 'mac', 'regex': r'\b([a-fA-F0-9]{2}[:\-][a-fA-F0-9]{2}[:\-][a-fA-F0-9]{2}[:\-]'
                                         r'[a-fA-F0-9]{2}[:\-][a-fA-F0-9]{2}[:\-][a-fA-F0-9]{2})\b', 'color': yellow},
                {'name': 'base64executable',
                 'regex': r'(TVpTAQEAAAAEAAAA//8AALgAAAA|TVoAAAAAAAAAAAAAAAAAAAAAAAA|'
                          r'TVqAAAEAAAAEABAAAAAAAAAAAAA|TVqAAAEAAAAEABAAAAAAAAAAAAA|'
                          r'TVpQAAIAAAAEAA8A//8AALgAAAA|TVqQAAMAAAAEAAAA//8AALgAAAA)', 'color': red},

                # Security
                {'name': 'yargen_import', 'regex': r'([A-Za-z]:\\|\.exe|\.pdb|\.scr|\.log|\.cfg|\.txt|\.dat|\.msi|\.com|\.bat|\.dll|\.pdb|\.vbs|\.tmp|\.sys)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(cmd.exe|system32|users|Documents and|SystemRoot|Grant|hello|password|process|log|This program cannot be run in DOS mode)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'\b(ftp|irc|smtp|command|GET|POST|tor2web|HEAD)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'\b(error|http[s]?|closed|version)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'\b(Mozilla|MSIE|Windows NT|Macintosh|Gecko|Opera|User\-Agent)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'\b(TEMP|Temporary|Appdata|Recycler)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'\b(scan|sniff|poison|fake|spoof|sweep|dump|flood|inject|forward|scan|vulnerable|cmagentaentials|cmagentas|coded|p0c|Content)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'\b(address[e]?[s]?|port[s]?|listen[s]?|process[e]?[s]?|service[s]?|mutex|pipe[s]?|key[s]?|lookup[s]?|connection[s]?)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'\b(coded | c0d3d |cr3w\b)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'\b(thawte|trustcenter|signing|class|crl|certificate|assembly)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(yyyy|hh:mm|dd/mm|mm/dd|%s:%s:)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'\b(cmd|pipe|tmp|temp|recycle|bin|secret|private|AppData|driver|config)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'\b(execute|run|shell|root|cimv2|login|exec|stdin|read|process|netuse|script|share)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'\b(user|pass|login|logon|token|cookie|cmagentas|hash|ticket|NTLM|LMHASH|kerberos|spnego|session|identif|account|login|privilege)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'\b(spy|logger|dark|cryptor|RAT\b|eye|comet|evil|xtreme|poison|meterpreter|metasploit)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'[\\](users|profiles|username|benutzer|Documents and Settings|Utilisateurs|Utenti|Usuários)[\\]', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(\\\\\.\\|kernel|.dll|usage|\\DosDevices\\)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(loader|cmdline|ntlmhash|lmhash|drop|infect|encrypt|exec|elevat|dump|target|victim|override|traverse|mutex|pawnde|exploited|shellcode|injected|spoofed)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(administrator|highest|SYSTEM|debug|dbg|admin|adm|root) privilege', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(\.exe|\.dll|\.sys)$', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(\\Release\\|\\Debug\\|\\bin|\\sbin)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(Management Support Team1|/c rundll32|DTOPTOOLZ Co.|net start|Exec|taskkill)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'^([\*\#]+ |\[[\*\-\+]\] |[\-=]> |\[[A-Za-z]\] )', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(!\.$|!!!$| :\)$| ;\)$|fucked|[\w]\.\.\.\.$)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(?:[A-Za-z0-9+/]{4}){30,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(LSASS|SAM|lsass.exe|cmd.exe|LSASRV.DLL)', 'color': magenta },
                ]

    # IP Regular Expressions
    # Source: https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
    # IPv6 RegEx
    ipv6_regex = r'\b(' \
                 r'([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|' \
                 r'([0-9a-fA-F]{1,4}:){1,7}:|' \
                 r'([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|' \
                 r'([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|' \
                 r'([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|' \
                 r'([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|' \
                 r'([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|' \
                 r'[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|' \
                 r':((:[0-9a-fA-F]{1,4}){1,7}|:)|' \
                 r'fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|' \
                 r'::(ffff(:0{1,4}){0,1}:){0,1}' \
                 r'((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}' \
                 r'(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|' \
                 r'([0-9a-fA-F]{1,4}:){1,4}:' \
                 r'((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}' \
                 r'(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])' \
                 r')\b'
    # IPv4 RegEx
    ipv4_regex = r'\b((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\b'
    ipv4 = re.compile(ipv4_regex)
    ipv6 = re.compile(ipv6_regex)

    def __init__(self, debug_mode, highlight_strings, case_insensitive, wait_time, dyn_col_regex, no_generic):
        self.debug_mode = debug_mode
        self.wait_time = int(wait_time)
        self.string_match_caseinsensitive = case_insensitive

        # No generic colorisation
        if no_generic:
            self.generic_colorisation = False

        # Highlight certain strings
        if highlight_strings:
            for string in highlight_strings[0]:
                self.highlight_strings.append(string)

        # Dynamic color assignment based on regex (default is IPv4/IPv6 detection)
        try:
            if dyn_col_regex != '':
                self.dynamic_color_regex = re.compile(dyn_col_regex)
                self.dynamic_color_mode = 'REGEX'
        except Exception:
            if self.debug_mode:
                traceback.print_exc()
            print("[E] Error while compiling the regex value of {0}".format(dyn_col_regex))

    def initialize_colors(self):
        """Loop through available components and create all available colors"""
        for fcolor, fcolor_code in self.FORE_COLORS.items():
            for bcolor, bcolor_code in self.BACK_COLORS.items():
                # if foreground and background is the same
                if fcolor == bcolor:
                    continue
                # Other unreadable combinations
                if fcolor == "green" and bcolor == "cyan":
                    continue
                if fcolor == "cyan" and bcolor == "green":
                    continue
                if self.debug_mode:
                    print(fcolor_code + bcolor_code + "Initialized COLOR")
                self.assigned_colors[fcolor_code+bcolor_code] = {}
                # Color is used for 'string' value - preset is empty
                self.assigned_colors[fcolor_code+bcolor_code]['string'] = ''
                # Color count - will be used to select a color that
                # has not been used for the longest time
                self.assigned_colors[fcolor_code+bcolor_code]['count'] = 0

    def get_available_color(self, string):
        """Returns an available color and assignes a string"""
        # Try to find a color that has not been used
        for color in self.assigned_colors:
            if self.assigned_colors[color]['string'] == '':
                self.assigned_colors[color]['string'] = string
                # Unused color found
                return color

        # If no unused color has been found - reuse the one that
        # has not been used for the most cycles
        less_used_color = ''
        max_cycle_count = 0
        for color in self.assigned_colors:
            if self.assigned_colors[color]['count'] > max_cycle_count:
                less_used_color = color
                max_cycle_count = self.assigned_colors[color]['count']
        # Reset this color
        self.assigned_colors[less_used_color]['count'] = 0
        self.assigned_colors[less_used_color]['string'] = string
        return less_used_color

    def get_color_for_string(self, string):
        """Returns a new or assigned color for a given string"""
        for color in self.assigned_colors:
            try:
                # Increase count for unused strings
                self.assigned_colors[color]['count'] += 1
            except Exception:
                # If integer overflow
                self.assigned_colors[color]['count'] = 0
                self.assigned_colors[color]['string'] = ''

            # already assigned
            if self.assigned_colors[color]['string'] == string:
                self.assigned_colors[color]['count'] = 0
                # Found color that has already assigned for that string
                return color

        # No color has yet assigned to the string
        return self.get_available_color(string)

    def colorize(self, line):
        """Colorizes the input line"""

        do_wait_for_keypress = False

        # IP colorization (assigned color mode)
        if self.dynamic_color_mode == 'IP':
            for match in self.ipv4.finditer(line):
                ip = match.group()
                color = self.get_color_for_string(ip)
                re_colorer = re.compile(r'({0})'.format(ip))
                line = re_colorer.sub(color + r'\1' + self.base_color, line)
            for match in self.ipv6.finditer(line):
                ip = match.group()
                color = self.get_color_for_string(ip)
                re_colorer = re.compile(r'({0})'.format(ip))
                line = re_colorer.sub(color + r'\1' + self.base_color, line)

        # Regex colorization
        if self.dynamic_color_mode == 'REGEX':
            for match in self.dynamic_color_regex.finditer(line):
                string = match.group()
                print(string)
                color = self.get_color_for_string(string)
                re_colorer = re.compile(r'({0})'.format(string))
                line = re_colorer.sub(color + r'\1' + self.base_color, line)

        # Regex colorization
        if self.generic_colorisation:
            for col in self.COLORIZER:
                try:
                    re_colorer = re.compile(col['regex'])
                    if re_colorer.groups == 1:
                        line = re_colorer.sub(col['color'] + r'\1' + self.base_color, line)
                    if re_colorer.groups == 2:
                        # Modes
                        mark_all = False
                        if 'mode' in col:
                            if col['mode'] == 'mark_all':
                                mark_all = True
                        # Default
                        if not mark_all:
                            line = re_colorer.sub(col['color'] + r'\1' + self.base_color + r'\2', line)
                        # Mark all
                        else:
                            line = re_colorer.sub(col['color'] + r'\1\2' + self.base_color, line)
                except Exception:
                    print("REGEX: %s" % col['regex'])
                    print("LINE: %s" % line)
                    traceback.print_exc()

        # String colorization (parameter)
        for string in self.highlight_strings:
            if self.string_match_caseinsensitive:
                if string.lower() in line.lower():
                    re_colorer = re.compile(r'({0})'.format(string), re.IGNORECASE)
                    line = re_colorer.sub(self.string_highlight + r'\1' + self.base_color, line)
                    if self.wait_time > 0:
                        do_wait_for_keypress = True
            else:
                if string in line:
                    re_colorer = re.compile(r'({0})'.format(string))
                    line = re_colorer.sub(self.string_highlight + r'\1' + self.base_color, line)
                    if self.wait_time > 0:
                        do_wait_for_keypress = True

        return line, do_wait_for_keypress

    def colorize_stdin(self):
        """Reads from STDIN line by line"""
        try:
            while True:
                line = sys.stdin.readline()
                if not line:
                    break  # EOF
                colorized_line, wait_for_keypress = self.colorize(line)
                sys.stdout.write(colorized_line)
                if wait_for_keypress:
                    self.await_keypress()
        except Exception:
            if self.debug_mode:
                traceback.print_exc()

    def await_keypress(self):
        time.sleep(self.wait_time)


if __name__ == '__main__':

    # Parse Arguments
    parser = argparse.ArgumentParser(description='Prisma - command line colorizer')

    parser.add_argument('-s', action='append', nargs='+', default=None, metavar='string',
                        help='Strings to highlight, separate with space (e.g. -s failed error)')
    parser.add_argument('-i', action='store_true', help='Case-insensitive search for strings', default=False)
    parser.add_argument('-w', metavar='seconds', help='Pause on string match (in seconds)', default=0)
    parser.add_argument('-r', metavar='regex', help='Use this regex for dynamic color assignment '
                                                    'instead of automatic IPv4/IPv6 detection', default='')
    parser.add_argument('-p', action='store_true', help='Pass ANSI codes, which is useful to retain'
                        'color, when piping to less', default=False)
    parser.add_argument('--nogeneric', action='store_true', default=False,
                        help='Disable generic colorisation (useful in cases of strange behavior)')
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

    args = parser.parse_args()

    # Colorama Init
    if(args.p):  # Do not strip ANSI codes
        init(strip=False)
    else:
        init()

    rainbow = Prisma(args.debug, args.s, args.i, args.w, args.r, args.nogeneric)
    rainbow.initialize_colors()
    rainbow.colorize_stdin()
