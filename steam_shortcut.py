#!/usr/bin/env python3
# MIT License
# 
# Copyright (c) 2026 sookyboo
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import argparse
import os
import platform
import shutil
import struct
import sys
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple, Optional


# ----------------------------
# AppID
# ----------------------------
def shortcut_appid(exe: str, app_name: str) -> int:
    combined = (exe + app_name).encode("utf-8")
    crc = zlib.crc32(combined) & 0xFFFFFFFF
    return crc | 0x80000000


# ----------------------------
# Steam path detection
# ----------------------------
def detect_steam_root() -> Optional[Path]:
    system = platform.system().lower()

    candidates: List[Path] = []
    home = Path.home()

    if "windows" in system:
        # Common Steam install locations
        pf86 = os.environ.get("PROGRAMFILES(X86)")
        pf = os.environ.get("PROGRAMFILES")
        if pf86:
            candidates.append(Path(pf86) / "Steam")
        if pf:
            candidates.append(Path(pf) / "Steam")
        # Also common custom location
        candidates.append(Path("C:/Steam"))
    else:
        # Linux / Steam Deck / Flatpak
        candidates.extend([
            home / ".steam" / "steam",
            home / ".local" / "share" / "Steam",
            home / ".var" / "app" / "com.valvesoftware.Steam" / "data" / "Steam",
            ])

    for c in candidates:
        if (c / "userdata").is_dir():
            return c

    return None


def choose_userdata_dir(steam_root: Path, steamid: Optional[str]) -> Tuple[Path, str]:
    userdata = steam_root / "userdata"
    if not userdata.is_dir():
        raise FileNotFoundError(f"No userdata dir under {steam_root}")

    if steamid:
        d = userdata / steamid
        if not d.is_dir():
            raise FileNotFoundError(f"SteamID folder not found: {d}")
        return d, steamid

    # Auto-pick: choose the SteamID that has a shortcuts.vdf with newest mtime
    best_dir: Optional[Path] = None
    best_id: Optional[str] = None
    best_mtime = -1.0

    for d in userdata.iterdir():
        if not d.is_dir():
            continue
        if not d.name.isdigit():
            continue
        vdf = d / "config" / "shortcuts.vdf"
        if vdf.exists():
            mtime = vdf.stat().st_mtime
            if mtime > best_mtime:
                best_mtime = mtime
                best_dir = d
                best_id = d.name

    # If none have shortcuts.vdf yet, pick the newest numeric folder by directory mtime
    if best_dir is None:
        for d in userdata.iterdir():
            if d.is_dir() and d.name.isdigit():
                mtime = d.stat().st_mtime
                if mtime > best_mtime:
                    best_mtime = mtime
                    best_dir = d
                    best_id = d.name

    if best_dir is None or best_id is None:
        raise FileNotFoundError(f"Could not find any SteamID folders under {userdata}")

    return best_dir, best_id


# ----------------------------
# Binary VDF parsing/writing (shortcuts.vdf)
# ----------------------------
SOH = 0x01  # text
STX = 0x02  # numeric
NUL = 0x00
BS = 0x08


def read_cstring(buf: bytes, i: int) -> Tuple[str, int]:
    j = buf.find(b"\x00", i)
    if j < 0:
        raise ValueError("Unterminated cstring")
    return buf[i:j].decode("utf-8", errors="replace"), j + 1


def read_u32(buf: bytes, i: int) -> Tuple[int, int]:
    """
      - normal: 4 bytes LE
      - 'soh' form: 0x01 then 3 bytes, interpreted as LE with a leading 0x00
    """
    if i >= len(buf):
        raise ValueError("Unexpected EOF reading u32")

    if buf[i] == SOH:
        if i + 4 > len(buf):
            raise ValueError("Unexpected EOF reading SOH-u32")
        b0, b1, b2 = buf[i + 1], buf[i + 2], buf[i + 3]
        val = struct.unpack("<I", bytes([0x00, b0, b1, b2]))[0]
        return val, i + 4
    else:
        if i + 4 > len(buf):
            raise ValueError("Unexpected EOF reading u32")
        val = struct.unpack("<I", buf[i:i + 4])[0]
        return val, i + 4


def write_text_line(key: str, value: str) -> bytes:
    return bytes([SOH]) + key.encode("utf-8") + b"\x00" + value.encode("utf-8") + b"\x00"


def write_u32_line(key: str, value: int) -> bytes:
    return bytes([STX]) + key.encode("utf-8") + b"\x00" + struct.pack("<I", value & 0xFFFFFFFF)


def write_stx_single_bool(key: str, value: bool) -> bytes:
    """
      0x02 key 0x00 0x01 0x00 0x00 <byte>
    """
    return bytes([STX]) + key.encode("utf-8") + b"\x00" + bytes([SOH, 0x00, 0x00, 0x01 if value else 0x00])


def parse_tags_block(buf: bytes, i: int) -> Tuple[List[str], int]:
    # expects: 0x00 "tags" 0x00 ... until BS then BS
    if buf[i] != NUL:
        raise ValueError("Expected NUL before tags")
    i += 1
    if buf[i:i + 4] != b"tags":
        raise ValueError("Expected 'tags'")
    i += 4
    if buf[i] != NUL:
        raise ValueError("Expected NUL after tags")
    i += 1

    tags: List[str] = []
    # read until BS
    while i < len(buf) and buf[i] != BS:
        if buf[i] != SOH:
            raise ValueError(f"Expected SOH in tag entry, got {buf[i]:02x}")
        i += 1
        _idx, i = read_cstring(buf, i)        # tag index string
        tag_name, i = read_cstring(buf, i)    # actual tag
        tags.append(tag_name)

    if i >= len(buf) or buf[i] != BS:
        raise ValueError("Expected BS at end of tags block")
    i += 1  # consume BS
    return tags, i


@dataclass
class Shortcut:
    appid: int
    app_name: str
    exe: str
    start_dir: str = ""
    icon: str = ""
    shortcut_path: str = ""
    launch_options: str = ""
    is_hidden: bool = False
    allow_desktop_config: bool = True
    allow_overlay: bool = True
    open_vr: int = 0
    devkit: int = 0
    devkit_game_id: str = ""
    devkit_override_appid: int = 0
    last_play_time: int = 0
    tags: List[str] = field(default_factory=list)


def parse_shortcuts_vdf(data: bytes) -> List[Shortcut]:
    # header: \0shortcuts\0
    if not data.startswith(b"\x00shortcuts\x00"):
        raise ValueError("Not a shortcuts.vdf (missing header)")

    i = len(b"\x00shortcuts\x00")
    shortcuts: List[Shortcut] = []

    while i < len(data):
        # End-of-file marker is usually BS BS
        if data[i:i + 2] == bytes([BS, BS]):
            break

        # each shortcut begins: NUL order NUL
        if data[i] != NUL:
            raise ValueError(f"Expected NUL at start of shortcut, got {data[i]:02x}")
        i += 1
        _order, i = read_cstring(data, i)

        fields_text: Dict[str, str] = {}
        fields_num: Dict[str, int] = {}

        # parse key/value lines until we hit NUL 'tags' NUL
        while True:
            if i >= len(data):
                raise ValueError("Unexpected EOF inside shortcut")

            # tags block starts with NUL "tags" NUL
            if data[i] == NUL and data[i + 1:i + 5] == b"tags" and data[i + 5:i + 6] == b"\x00":
                break

            t = data[i]
            i += 1
            if t == SOH:
                key, i = read_cstring(data, i)
                val, i = read_cstring(data, i)
                fields_text[key.lower()] = val
            elif t == STX:
                key, i = read_cstring(data, i)
                val, i = read_u32(data, i)
                fields_num[key.lower()] = val
            else:
                raise ValueError(f"Unknown line type {t:02x} at offset {i-1}")

        tags, i = parse_tags_block(data, i)

        # After tags block, shortcut ends with an extra BS
        if i >= len(data) or data[i] != BS:
            raise ValueError("Expected BS at end of shortcut record")
        i += 1  # consume BS

        # Steam sometimes has an extra BS; your writer always writes two BS at end of shortcut
        # We tolerate a second BS here if present.
        if i < len(data) and data[i] == BS:
            i += 1

        appid = fields_num.get("appid", 0) or fields_num.get("app_id", 0)
        sc = Shortcut(
            appid=appid,
            app_name=fields_text.get("appname", ""),
            exe=fields_text.get("exe", ""),
            start_dir=fields_text.get("startdir", ""),
            icon=fields_text.get("icon", ""),
            shortcut_path=fields_text.get("shortcutpath", ""),
            launch_options=fields_text.get("launchoptions", ""),
            is_hidden=(fields_num.get("ishidden", 0) != 0),
            allow_desktop_config=(fields_num.get("allowdesktopconfig", 0) != 0),
            allow_overlay=(fields_num.get("allowoverlay", 0) != 0),
            open_vr=fields_num.get("openvr", 0),
            devkit=fields_num.get("devkit", 0),
            devkit_game_id=fields_text.get("devkitgameid", ""),
            devkit_override_appid=fields_num.get("devkitoverrideappid", 0),
            last_play_time=fields_num.get("lastplaytime", 0),
            tags=tags,
        )
        shortcuts.append(sc)

    return shortcuts


def write_shortcuts_vdf(shortcuts: List[Shortcut]) -> bytes:
    out = bytearray()
    out += b"\x00shortcuts\x00"

    for idx, sc in enumerate(shortcuts):
        out += bytes([NUL])
        out += str(idx).encode("utf-8") + b"\x00"

        out += write_u32_line("appid", sc.appid)
        out += write_text_line("AppName", sc.app_name)
        out += write_text_line("Exe", sc.exe)
        out += write_text_line("StartDir", sc.start_dir)
        out += write_text_line("icon", sc.icon)
        out += write_text_line("ShortcutPath", sc.shortcut_path)
        out += write_text_line("LaunchOptions", sc.launch_options)
        out += write_u32_line("IsHidden", 1 if sc.is_hidden else 0)

        out += write_stx_single_bool("AllowDesktopConfig", sc.allow_desktop_config)
        out += write_stx_single_bool("AllowOverlay", sc.allow_overlay)

        out += write_u32_line("openvr", sc.open_vr)
        out += write_u32_line("Devkit", sc.devkit)
        out += write_text_line("DevkitGameID", sc.devkit_game_id)
        out += write_u32_line("DevkitOverrideAppID", sc.devkit_override_appid)
        out += write_u32_line("LastPlayTime", sc.last_play_time)

        # tags block
        out += bytes([NUL]) + b"tags" + bytes([NUL])
        for t_idx, tag in enumerate(sc.tags):
            out += bytes([SOH])
            out += str(t_idx).encode("utf-8") + b"\x00"
            out += tag.encode("utf-8") + b"\x00"

        out += bytes([BS, BS])

    out += bytes([BS, BS])
    return bytes(out)


# ----------------------------
# Artwork install
# ----------------------------
def install_artwork(grid_dir: Path, appid: int,
                    grid: Optional[Path] = None,
                    hero: Optional[Path] = None,
                    logo: Optional[Path] = None,
                    portrait: Optional[Path] = None) -> None:
    grid_dir.mkdir(parents=True, exist_ok=True)
    if grid:
        shutil.copyfile(grid, grid_dir / f"{appid}.png")
    if portrait:
        shutil.copyfile(portrait, grid_dir / f"{appid}p.png")
    if hero:
        shutil.copyfile(hero, grid_dir / f"{appid}_hero.png")
    if logo:
        shutil.copyfile(logo, grid_dir / f"{appid}_logo.png")


# ----------------------------
# Main
# ----------------------------
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Add/update Steam shortcuts.vdf and (optionally) install grid artwork. No dependencies."
    )
    ap.add_argument("--steam-root", type=str, default=None, help="Path to Steam root (auto-detect if omitted)")
    ap.add_argument("--steamid", type=str, default=None, help="SteamID folder under userdata/ (auto-pick if omitted)")

    ap.add_argument("--name", required=True, help="AppName shown in Steam (e.g. 'My Game')")
    ap.add_argument("--exe", required=True, help="Exe path (Steam usually stores this quoted on Windows)")
    ap.add_argument("--startdir", default="", help="Working directory (StartDir)")
    ap.add_argument("--icon", default="", help="Icon path")
    ap.add_argument("--launch", default="", help="LaunchOptions")
    ap.add_argument("--shortcutpath", default="", help="ShortcutPath")
    ap.add_argument("--tags", default="", help="Comma-separated tags (e.g. Installed,Ready TO Play)")
    ap.add_argument("--hidden", action="store_true", help="Set IsHidden=1")
    ap.add_argument("--no-overlay", action="store_true", help="Disable AllowOverlay")
    ap.add_argument("--no-desktop-config", action="store_true", help="Disable AllowDesktopConfig")

    # Artwork optional
    ap.add_argument("--grid", type=str, default=None, help="Grid PNG -> {appid}.png")
    ap.add_argument("--portrait", type=str, default=None, help="Portrait grid PNG -> {appid}p.png")
    ap.add_argument("--hero", type=str, default=None, help="Hero PNG -> {appid}_hero.png")
    ap.add_argument("--logo", type=str, default=None, help="Logo PNG -> {appid}_logo.png")

    args = ap.parse_args()

    steam_root = Path(args.steam_root) if args.steam_root else detect_steam_root()
    if not steam_root:
        print("Could not auto-detect Steam root. Pass --steam-root.", file=sys.stderr)
        return 2

    userdir, chosen_id = choose_userdata_dir(steam_root, args.steamid)
    cfg = userdir / "config"
    vdf_path = cfg / "shortcuts.vdf"
    cfg.mkdir(parents=True, exist_ok=True)

    exe = args.exe
    name = args.name
    appid = shortcut_appid(exe, name)

    tags = [t.strip() for t in args.tags.split(",") if t.strip()]
    sc_new = Shortcut(
        appid=appid,
        app_name=name,
        exe=exe,
        start_dir=args.startdir,
        icon=args.icon,
        shortcut_path=args.shortcutpath,
        launch_options=args.launch,
        is_hidden=bool(args.hidden),
        allow_overlay=not args.no_overlay,
        allow_desktop_config=not args.no_desktop_config,
        tags=tags,
        last_play_time=0,
    )

    existing: List[Shortcut] = []
    if vdf_path.exists():
        data = vdf_path.read_bytes()
        existing = parse_shortcuts_vdf(data)

    # Update if exists by appid, else append
    updated = False
    for idx, sc in enumerate(existing):
        if sc.appid == appid:
            existing[idx] = sc_new
            updated = True
            break
    if not updated:
        existing.append(sc_new)

    out_bytes = write_shortcuts_vdf(existing)

    # Backup then write
    if vdf_path.exists():
        bak = vdf_path.with_suffix(".vdf.bak")
        shutil.copyfile(vdf_path, bak)

    vdf_path.write_bytes(out_bytes)

    # Artwork (optional)
    grid_dir = cfg / "grid"
    if args.grid or args.hero or args.logo or args.portrait:
        install_artwork(
            grid_dir=grid_dir,
            appid=appid,
            grid=Path(args.grid) if args.grid else None,
            hero=Path(args.hero) if args.hero else None,
            logo=Path(args.logo) if args.logo else None,
            portrait=Path(args.portrait) if args.portrait else None,
        )

    action = "Updated" if updated else "Added"
    print(f"{action} shortcut for SteamID {chosen_id}")
    print(f"shortcuts.vdf: {vdf_path}")
    print(f"appid: {appid} (0x{appid:08x})")
    if args.grid or args.hero or args.logo or args.portrait:
        print(f"artwork dir: {grid_dir}")
    print("Restart Steam to see changes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
