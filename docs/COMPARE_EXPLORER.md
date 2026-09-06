# Compare Explore · 구현 및 검증

두 세션의 Explore 그래프와 **선택에 따른 Summary 비교**를 구현했습니다. 기존 Explore 그래프 렌더러와 정확한 선택 집계를 재사용하며, 각 세션의 request key·파일 근거·시간 원점·필터·비동기 결과는 분리합니다.

## 사용

1. Compare에서 Keep current as baseline을 누르고 다음 세션을 열거나 기록합니다. Open baseline session / Open current session으로 기존 두 세션을 열 수도 있습니다.
2. 공통 preset, X/Y metric, Color Category, point size와 사용자 색상을 정합니다. 시간은 각 원본의 시작 기준 상대 ms입니다. Link X/Y view는 기본 켜짐이며, 수동 축 범위·Zoom·Back으로 탐색합니다.
3. Comparison filters에서 공통 시간/Read·Write/신뢰도/프로세스 이름을 정하고 Apply합니다. PID/TID·파일·device는 세션별로 입력합니다. 일반 Explore 필터는 비교 화면과 분리합니다.
4. 양쪽에서 점·영역을 독립적으로 선택합니다. Select same area in both는 영역 좌표를 두 세션에 적용합니다. 점 클릭은 다른 세션의 요청을 임의로 선택하지 않습니다.
5. 오른쪽 Selection Summary에서 Data Count, End−Start, Read/Write 용량·MiB/s와 Current−Baseline 차이를 확인합니다. Read / Write latency percentiles를 펼치면 P50/P90/P95/P99/Max와 유효 표본 수가 표시됩니다. Files / Processes / Distributions / I/O details에서 선택된 대상과 근거를 확인합니다. 작은 창에서는 패널이 그래프 아래로 이동합니다.
6. Export comparison JSON은 선택 키, 파일 후보·프로세스, 필터·원점·축 범위·통계와 정의를 저장합니다. 원본 파일 덮어쓰기를 차단합니다.

## 검증

- 호스트 **99개 통과**, 환경 의존 5개는 기본 실행 제외. 이번 Compare 회귀 9개: 상대 원점, 세션 격리, 필터, 기준 보관, 미측정값, 오래된 비동기 결과, 로딩 실패 보존, export/원본 보호 및 페이지 범위 포함. Windows GNU release build 및 Clippy -D warnings 통과.
- 네이티브 입력 11조건: 점 1/184건, 동일 영역 146/146건, Read 필터 139/139건, 한쪽 빈 선택 0/184건, Zoom/Back, Files/Processes/Distributions/I/O details, 작은 창 800×600 logical / 200% renderer scale, 10만 I/O씩 두 세션. 행렬 (local acceptance artifact)
- 이전 실제 trace 184 I/O와, timestamp·파일 이름·프로세스 이름·bytes를 변경한 **합성 비교 fixture**를 사용했습니다. 두 실제 기기 또는 실제 성능 전후 비교라는 뜻이 아닙니다.
- 10만 I/O × 2: 시작부터 두 비교 Summary 준비 **3.17초**. 영역 71,488건씩 선택 응답 **266 / 267ms** (스냅샷 준비·백그라운드 계산·UI 수신 포함), 계산 자체 201 / 179ms. UI update p95 7.1ms, 최대 391.1ms. 전체 입력 대기·스크린샷·종료를 포함한 자동 실행은 5.60초입니다. 관측 working set 651.0MiB. 최종 성능 (local acceptance artifact)
- 같은 PC i7-13700H / 31.6 GiB RAM. 이 데이터와 조건에서 준비·선택은 5초 미만이며, 모든 크기·모든 파일 근거 밀도의 보장은 아닙니다.

## 화면

선택 그래프 (local acceptance artifact) · Files 비교 (local acceptance artifact) · Processes 비교 (local acceptance artifact) · High Contrast 분포 (local acceptance artifact) · 작은 창 (local acceptance artifact)

## 범위와 남은 작업

Side-by-side 및 작은 창의 세로 배치를 제공합니다. 그래프 중첩은 추가하지 않았습니다. 기본 비교는 현재 유지된 최대 10만 I/O 범위이며, 원본 전체의 무제한 분석이나 의미상 서로 다른 프로세스/파일의 자동 동치 판정을 하지 않습니다. 그래프에 없는 측정은 통계에 0을 넣지 않습니다. 원본 I/O 상세의 request key는 항상 세션 단위입니다.

독립 리뷰가 아닌 구현자 통합 검토입니다. 실제 OS 전체 접근성·모든 축/색/필터의 조합을 인증한 것은 아닙니다. 이전의 간헐적 native 시작 오류는 이번 비교 수정으로 해결했다고 주장하지 않습니다. Non-root Perfetto 수집과 실제 GUI 검증 범위는 [PERFETTO_BLOCK_IO.md](PERFETTO_BLOCK_IO.md)를 참조합니다.

빈 선택 그래프 정렬 결함을 수정하고, 빈/채워진 비교 그래프의 동일 축 범위에서 상단·폭·비중첩을 확인하는 회귀 테스트를 추가했습니다. 같은 조건의 네이티브 화면 재검증도 통과했습니다.
