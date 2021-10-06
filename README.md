# 최신 ARM64 리눅스 커널 5.10 분석

## 커뮤니티: IAMROOT 18차
- [www.iamroot.org][#iamroot] | IAMROOT 홈페이지
- [jake.dothome.co.kr][#moonc] | 문c 블로그

[#iamroot]: http://www.iamroot.org
[#moonc]: http://jake.dothome.co.kr

## History

- 첫 모임: 2015년 5월 22일 (총인원 약 90여명 - 약 50여명 zoom 접속)

- [https://band.us/@iamroot18][#band] | iamroot18 밴드

[#iamroot]: http://www.iamroot.org
[#moonc]: http://jake.dothome.co.kr
[#band]: https://band.us/@iamroot18


### 0주차
2021.05.22, Zoom 온라인(5x명 접속 / 총인원 9x명)
- Orientation (3시간)

### 1주차
- 2021.05.29, Zoom 온라인(53명 참석).
- pm 03:00 ~ pm 10:00
- 리눅스 커널 내부구조 (p10 ~ p54 중간)

### 2주차
- 2021.06.05, Zoom 온라인(52명 참석)
- pm 03:00 ~ pm 10:00
- 리눅스 커널 내부구조 (p54 ~ p81)

### 3주차
- 2021.06.12, Zoom 온라인(44명 참석)
- pm 03:00 ~ pm 10:00
- 리눅스 커널 내부구조 (p81 ~ p100)

### 4주차
- 2021.06.19, Zoom 온라인(40명 참석)
- pm 03:00 ~ pm 10:00
- 리눅스 커널 내부구조 (p100 ~ p124)

### 5주차
- 2021.06.26, Zoom 온라인(36명 참석)
- pm 03:00 ~ pm 10:00
- 리눅스 커널 내부구조 (p124 ~ p171)

### 6주차
- 2021.07.03, Zoom 온라인(36명 참석)
- pm 03:00 ~ pm 10:00
- 리눅스 커널 내부구조 ( ~ end)

### 7주차
- 2021.07.10, Zoom 온라인(43명 참석)
- ARM System Developers Guide 책, ~p69, 3.3.3 Multiple-Register Transfer

### 8주차
- 2021.07.17, Zoom 온라인(34명 참석)
- ARM System Developers Guide 완료 
- head.S의 preserve_boot_args() -> __inval_dcache_area() 

### 9주차
- 2021.07.24, Zoom 온라인(36명 참석)
- ARM Programmers Guide: ~p161
- head.S의 el2_setup 진행중

### 10주차
- 2021.07.31, Zoom 온라인(31명 참석)
- ARM Programmers Guide: ~p190
- head.S의 el2_setup 진행중

### 11주차
- 2021.08.07, Zoom 온라인(26명 참석)
- ARM Programmers Guide: 완료
- head.S의 el2_setup 진행중

### 12주차
- 2021.08.14, Zoom 온라인(27명 참석)
- head.S의 __create_page_tables의 첫 번째 map_memory 직전 

### 13주차
- 2021.08.21, Zoom 온라인(21명 참석)
- head.S: __cpu_setup()의 tcr_compute_pa_size 매크로 직전

### 14주차
- 2021.08.28, Zoom 온라인(27명 참석)
- head.S: __primary_switch()의 __relocate_kernel() 진행중

### 15주차
- 2021.09.04, Zoom 온라인(22명 참석)
- head.S: CONFIG_RANDOMIZE_BASE 커널 옵션 부분 진행중

### 16주차
- 2021.09.11, Zoom 온라인(22명 참석)
- start_kernel() 시작 - boot_cpu_init() 직전까지

### 17주차
- 2021.09.18, Zoom 온라인(22명 참석)
- barrier, atomic

### 18주차
- 2021.09.25, Zoom 온라인(18명 참석)
- bitops, bitmap, cpumask, spinlock 진행중

### 19주차
- 2021.10.02, Zoom 온라인(19명 참석)
- spinlock, early_fixmap_init() 진행중
