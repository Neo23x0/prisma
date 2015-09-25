#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-

"""
Prisma

Automatic Command Line Colorizer
by Florian Roth
"""
__version__ = '0.1'

import sys
import argparse
import re
import traceback
from colorama import Fore, Back, Style
from colorama import init

class Rainbow():

    debug_mode = False

    # Defined colors
    base_color = Fore.WHITE+Back.BLACK+Style.NORMAL
    cyan_highlight = Fore.CYAN+Back.BLACK+Style.BRIGHT
    green_highlight = Fore.GREEN+Back.BLACK+Style.BRIGHT
    red = Fore.RED+Back.BLACK+Style.BRIGHT
    cyan_back = Fore.BLACK+Back.CYAN
    green_back = Fore.WHITE+Back.GREEN
    yellow = Fore.YELLOW+Back.BLACK
    green = Fore.GREEN+Back.BLACK+Style.BRIGHT
    magenta = Fore.MAGENTA+Back.BLACK
    magenta_back = Fore.WHITE+Back.MAGENTA

    # Application
    COLORIZER = [
                # General
                {'name': 'uppercase_keywords', 'regex': r'\b([A-Z]{3,})\b', 'color': cyan_highlight},
                {'name': 'keys_logline', 'regex': r'([A-Z_]{2,}:[\s\t])', 'color': cyan_highlight},
                {'name': 'service', 'regex': r'(\s[A-Za-z]+\[[0-9]+\]:)', 'color': green_highlight},
                {'name': 'string', 'regex': r'(\'[^\']+\')', 'color': yellow},
                {'name': 'id', 'regex': r'(\[[0-9+]+\])', 'color': green},
                {'name': 'tag', 'regex': r'(<[a-zA-Z_]+>)', 'color': green_back},
                {'name': 'key', 'regex': r'\b([a-zA-Z]{2,}[a-zA-Z0-9_]+[=:])([\s\w\t])', 'color': green},

                # Specific
                {'name': 'exclamation', 'regex': r'((?![0-9]{2}m) [A-Za-z0-9\-\s\']+!)$', 'color': red},
                {'name': 'date', 'regex': r'\b([A-Z][a-z][a-z][\s]?[\s][0-9]{1,2}[\s][0-9:]+)(\s[0-9]{4}|)\b', 'color': magenta_back, 'mode': 'mark_all'},
                {'name': 'IP', 'regex': r'([1-2]?[0-9]?[0-9]\.[1-2]?[0-9]?[0-9]\.[1-2]?[0-9]?[0-9]\.[1-2]?[0-9]?[0-9])', 'color': yellow },
                {'name': 'IP', 'regex': r'\b([a-f0-9]{4}:[a-f0-9:\.]+)\b', 'color': yellow },
                {'name': 'env_var_windows', 'regex': r'(%[A-Z_]+%)', 'color': yellow },
                {'name': 'env_var_linux', 'regex': r'\b($[A-Z_])\b', 'color': yellow },
                {'name': 'success', 'regex': r'([Ss]ucce[a-z]+)\b', 'color': green},
                {'name': 'failure', 'regex': r'([Ff]ail[a-z]+)\b', 'color': red},
                {'name': 'success', 'regex': r'([Aa]ccept[a-z]+|Permit[a-z]+)\b', 'color': green},
                {'name': 'denied', 'regex': r'([Dd]enied|[Dd]eny)\b', 'color': red},
                {'name': 'rejected', 'regex': r'([Rr]ejected)\b', 'color': red},
                {'name': 'granted', 'regex': r'([Gg]ranted)\b', 'color': green},
                {'name': 'blocked', 'regex': r'([Bb]locked)\b', 'color': red},
                {'name': 'filepath_linux', 'regex': r'(/[^\s]+/[^\s]+)\b', 'color': green},
                {'name': 'filepath_windows', 'regex': r'([C-Z]:\\[^\s]+)\b', 'color': green},

                # Security
                {'name': 'yargen_import', 'regex': r'([A-Za-z]:\\|\.exe|\.pdb|\.scr|\.log|\.cfg|\.txt|\.dat|\.msi|\.com|\.bat|\.dll|\.pdb|\.vbs|\.tmp|\.sys)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(cmd.exe|system32|users|Documents and|SystemRoot|Grant|hello|password|process|log)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(ftp|irc|smtp|command|GET|POST|tor2web|HEAD)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(error|http[s]?|closed|version)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(Mozilla|MSIE|Windows NT|Macintosh|Gecko|Opera|User\-Agent)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(TEMP|Temporary|Appdata|Recycler)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(scan|sniff|poison|fake|spoof|sweep|dump|flood|inject|forward|scan|vulnerable|cmagentaentials|cmagentas|coded|p0c|Content)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(address[e]?[s]?|port[s]?|listen[s]?|process[e]?[s]?|service[s]?|mutex|pipe[s]?|key[s]?|lookup[s]?|connection[s]?)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(coded | c0d3d |cr3w\b)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(thawte|trustcenter|signing|class|crl|certificate|assembly)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(yyyy|hh:mm|dd/mm|mm/dd|%s:%s:)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(cmd|pipe|tmp|temp|recycle|bin|secret|private|AppData|driver|config)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(execute|run|system|shell|root|cimv2|login|exec|stdin|read|process|netuse|script|share)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(user|pass|login|logon|token|cookie|cmagentas|hash|ticket|NTLM|LMHASH|kerberos|spnego|session|identif|account|login|privilege)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(spy|logger|dark|cryptor|RAT\b|eye|comet|evil|xtreme|poison|meterpreter|metasploit)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'[\\](users|profiles|username|benutzer|Documents and Settings|Utilisateurs|Utenti|Usuários)[\\]', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(\\\\\.\\|kernel|.dll|usage|\\DosDevices\\)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(loader|cmdline|ntlmhash|lmhash|drop|infect|encrypt|exec|elevat|dump|target|victim|override|traverse|mutex|pawnde|exploited|shellcode|injected|spoofed)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(administrator|highest|system|debug|dbg|admin|adm|root) privilege', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(\.exe|\.dll|\.sys)$', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(\\Release\\|\\Debug\\|\\bin|\\sbin)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(Management Support Team1|/c rundll32|DTOPTOOLZ Co.|net start|Exec|taskkill)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'^([\*\#]+ |\[[\*\-\+]\] |[\-=]> |\[[A-Za-z]\] )', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(!\.$|!!!$| :\)$| ;\)$|fucked|[\w]\.\.\.\.$)', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(?:[A-Za-z0-9+/]{4}){30,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$', 'color': magenta },
                {'name': 'yargen_import', 'regex': r'(LSASS|SAM|lsass.exe|cmd.exe|LSASRV.DLL)', 'color': magenta },
                ]

    def __init__(self, debug_mode):
        self.debug_mode = debug_mode

    def colorize(self, line):
        """Colorizes the input line"""
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
            except Exception, e:
                print "REGEX: %s" % col['regex']
                print "LINE: %s" % line
                traceback.print_exc()
        return line

    def colorize_stdin(self):
        """Reads from STDIN line by line"""
        try:
            while True:
                line = sys.stdin.readline()
                if not line:
                    break # EOF
                sys.stdout.write(self.colorize(line))
        except Exception, e:
            if self.debug_mode:
                traceback.print_exc()


if __name__ == '__main__':

    # Parse Arguments
    parser = argparse.ArgumentParser(description='Prisma - command line colorizer')
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

    args = parser.parse_args()

    # Colorama Init
    init()

    rainbow = Rainbow(args.debug)
    rainbow.colorize_stdin()
