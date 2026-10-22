import os
import sys
from typing import List, Optional, Tuple

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

COLOR_RED = "\033[1;31m"
COLOR_GREEN = "\033[1;32m"
COLOR_YELLOW = "\033[1;33m"
COLOR_BLUE = "\033[1;34m"
COLOR_MAGENTA = "\033[1;35m"
COLOR_CYAN = "\033[1;36m"
COLOR_WHITE = "\033[1;37m"
COLOR_GRAY = "\033[90m"

BG_RED = "\033[1;97;41m"
BG_GREEN = "\033[1;97;42m"
BG_YELLOW = "\033[1;97;43m"
BG_BLUE = "\033[1;97;44m"
BG_GRAY = "\033[1;97;100m"

def is_color_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return sys.stdout.isatty()

def c(text: str, code: str) -> str:
    if not is_color_enabled():
        return text
    return f"{code}{text}{RESET}"

def badge(label: str, variant: str = "blue") -> str:
    if not is_color_enabled():
        return f"[{label}]"
    
    mapping = {
        "red": BG_RED,
        "green": BG_GREEN,
        "yellow": BG_YELLOW,
        "blue": BG_BLUE,
        "cyan": COLOR_CYAN,
        "gray": BG_GRAY,
    }
    bg = mapping.get(variant, BG_BLUE)
    return f"{bg} {label} {RESET}"

def badge_outline(label: str, variant: str = "blue") -> str:
    if not is_color_enabled():
        return f"[{label}]"
    
    mapping = {
        "red": COLOR_RED,
        "green": COLOR_GREEN,
        "yellow": COLOR_YELLOW,
        "blue": COLOR_BLUE,
        "cyan": COLOR_CYAN,
        "gray": COLOR_GRAY,
    }
    color = mapping.get(variant, COLOR_BLUE)
    return f"{color}[{label}]{RESET}"

def print_header(title: str, subtitle: str = "CVE-2026-109618/19 DEFENSE & INOCULATION") -> None:
    width = 68
    box_top = f"┌{'─' * (width - 2)}┐"
    box_bot = f"└{'─' * (width - 2)}┘"
    
    print()
    print(c(box_top, COLOR_CYAN))
    title_str = f"anti-php2shell :: {title.upper()}"
    print(f"{c('│', COLOR_CYAN)}  {c(title_str, BOLD + COLOR_WHITE)}")
    print(f"{c('│', COLOR_CYAN)}  {c(subtitle, COLOR_GRAY)}")
    print(c(box_bot, COLOR_CYAN))
    print()

def print_card(title: str, rows: List[Tuple[str, str]], width: int = 68) -> None:
    title_bar = f"── {title} "
    fill = max(0, width - len(title_bar) - 2)
    print(c(f"┌{title_bar}{'─' * fill}┐", COLOR_GRAY))
    for key, val in rows:
        key_padded = f"{key:<20}"
        print(f"{c('│', COLOR_GRAY)}  {c(key_padded, BOLD + COLOR_WHITE)} : {val}")
    print(c(f"└{'─' * (width - 2)}┘", COLOR_GRAY))
    print()
