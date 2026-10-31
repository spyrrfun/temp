# temp

CTF·보안 연구용 샘플 코드 저장소.

## brop_dump.py — Blind ROP 바이너리 덤퍼 (pwntools)

바이너리를 전혀 모르는(blind) 원격 서비스에서 스택 오버플로만으로
stop gadget → 1-pop gadget(pop rdi; ret) → puts@plt를 순차 탐색해
.text를 바이트 단위로 덤프하는 샘플.

```bash
pip install pwntools
python3 brop_dump.py <host> <port> --offset 72
# 예: python3 brop_dump.py 127.0.0.1 9999 --offset 72 --banner "Welcome"
```

로컬 테스트 서버 예(fork 방식):

```bash
socat TCP-LISTEN:9999,reuseaddr,fork EXEC:./challenge
```

참고:
- Blind ROP 기법 원논문 "Blind ROP: Exploiting Single-Tick Memory Vulnerabilities" (2014)
- HCTF 2016 "brop" 계열 문제
- pwntools 문서: https://docs.pwntools.com

주의: 합법적 권한이 있는 대상(CTF·자체 테스트 환경)에서만 사용할 것.
