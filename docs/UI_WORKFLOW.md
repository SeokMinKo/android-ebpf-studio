# Android eBPF Storage Studio 개선판 사용법

기존 설치 위치의 앱을 실행하면 됩니다. 폰이 없을 때는 Start가 비활성화됩니다.

1. Root 폰을 USB로 연결하고 USB 디버깅을 허용합니다.
2. 여러 폰이 있으면 분석할 폰을 선택합니다.
3. **Start analysis**를 누르고 폰에서 작업합니다. Root·커널 점검과 추적 준비는 자동입니다.
4. **Stop & analyze**를 누르면 세션 저장 후 분석 화면으로 이동합니다.

**Explore → Select**에서 점을 클릭하거나 영역을 드래그하면 오른쪽에 선택 요약이 표시됩니다.

- Data Count, 시간 범위, Read/Write Size·Throughput
- Read/Write Chunk Pie, Random/Sequential/Unknown Pie
- Read/Write P50·P90·P95·P99·Max latency
- 파일 경로·device/inode·신뢰도와 프로세스 이름·PID/TID
- 파일/프로세스별 I/O 수, Read/Write 크기, 최대 지연시간

**Zoom selection**으로 확대하고 **Back**으로 돌아갑니다. 파일 또는 프로세스의 Filter 버튼은 선택했던 I/O 안에서 해당 항목으로 범위를 좁힙니다. 여러 파일 후보의 바이트를 합산하면 중복 계산이 될 수 있습니다.

그래프 위 **Color Category**에서 Read/Write, Sequential/Random, 크기, 프로세스, 파일, Origin, 신뢰도 등의 색상 분류를 선택합니다. **Point size (px)**로 Scatter 점의 지름을 2–20 범위에서 조절합니다. **Colors · customize category colors**를 펼치고 색상 칸을 클릭하면 RGB 색을 직접 정할 수 있습니다. **Auto**는 해당 항목, **Reset category colors**는 현재 분류 전체를 기본색으로 되돌립니다. 설정은 앱을 정상 종료할 때 저장됩니다.

오른쪽 패널은 독립적으로 스크롤할 수 있습니다. 작은 창에서는 **Device / Views**에서 기기와 분석 화면을 선택합니다. Light, Dark, HighContrast, System은 상단 테마 메뉴에 있습니다.

원본 세션은 `%LOCALAPPDATA%\AndroidEbpfStudio\sessions`에 자동 저장됩니다. 상단 **Session → Open session**으로 다시 열고 **Session → Export CSV**로 원본 이벤트와 분석 요약을 내보낼 수 있습니다. 기기 탐지 기록은 같은 앱 데이터 폴더의 `logs\<session-id>\device-profile.json`에 저장됩니다.

현재 상세 분석은 최대 10만 완료 I/O를 유지합니다. 원본 전체는 NDJSON에 남습니다. 이 빌드는 폰 없이 호스트·시뮬레이터·과거 실제 세션 재생으로 검증했으며, 실제 폰에서 새로 수집하는 검증은 아직 하지 못했습니다.

## X/Y축 범위 직접 조절

Explore → **Axis ranges · X / Y Min–Max**를 펼칩니다. 현재 축 단위(예: Time ms, Sector)로 Min/Max를 입력하고 **Apply X**, **Apply Y**, **Apply X + Y**를 누릅니다. 한 축만 적용하면 다른 축은 유지됩니다.

**Use current view**는 현재 확대/이동한 범위를 입력란에 가져옵니다. **Auto range**는 현재 표시 데이터에 자동으로 맞춥니다. 오른쪽 **Back**은 수동 적용·Auto·Zoom 이전 범위로 돌아갑니다. 범위 변경은 화면 확대이며 Summary의 선택 데이터나 분석 필터를 바꾸지 않습니다. 범위값은 세션/축 변경 시 초기화됩니다. 작은 창에서는 가운데 영역을 스크롤하여 입력란과 그래프를 확인할 수 있습니다.

Min < Max인 유한 숫자를 입력해야 하며 소수와 지수 표기(1e6)를 지원합니다. 잘못된 입력은 이유를 표시하고 기존 화면을 유지합니다. 이 범위 조절은 Explore의 모든 X/Y metric 조합에 적용됩니다.

## 과거 구간 재분석과 상세 내보내기

**Reanalyze time range**를 펼치고 세션 시작 기준 Start/End(ms)를 입력한 뒤 **Reanalyze interval**을 누르면 원본에서 그 구간을 다시 읽습니다. 완료 시각이 구간 안에 있는 I/O를 포함합니다. 최근 10만 건에서 사라진 오래된 상세도 복원할 수 있습니다. **Restore full session**으로 돌아오며, **Cancel**이나 오류 발생 시 기존 분석을 유지합니다. 한 구간이 10만 I/O를 넘거나 근거 데이터가 너무 많으면 더 좁은 구간을 안내합니다.

Explore 그래프 아래 **Completed block I/O** 테이블은 현재 필터에 맞는 모든 유지 중인 상세 행을 스크롤하여 보여줍니다. 행의 **Open I/O** 버튼을 클릭하거나 포커스 후 Enter를 누르면 Investigate에서 파일 근거와 개별 요청을 확인합니다.

**Session → Export view**는 현재 필터에 해당하는 I/O, 파일 후보, 그래프 관계와 분석 조건을 별도 NDJSON 분석 결과로 저장합니다. Select만 한 경우에는 Summary의 필터 기능으로 분석 대상을 좁힌 다음 내보냅니다. 이 결과 파일은 분석용이며 **Open session**에서 다시 분석할 원본은 자동 저장된 세션 NDJSON입니다. 원본 파일을 내보내기 대상으로 지정하는 것은 차단합니다.

종료 시각이 없는 관측점은 지연시간이 **Not measured**입니다. 해당 축에 그릴 수 없는 I/O는 그래프 점에서 제외되지만 원본과 상세 테이블에 남습니다.

## 화면별 사용 목적

- **Overview**: 가장 긴 I/O, 가장 바쁜 1초, 전송량이 큰 block issuer, 미해결 FilePath를 먼저 확인합니다. 각 행의 버튼으로 해당 요청 설명 또는 필터가 적용된 Explore로 바로 이동합니다. 큰 값 자체가 결함을 의미하지는 않습니다.
- **Explore**: 시간·프로세스·파일·기기·방향·신뢰도 필터와 그래프로 후보를 좁힙니다. Select로 선택한 결과는 오른쪽 패널에 표시됩니다.
- **Investigate**: 한 요청의 queue wait, issue-to-completion 시간, FilePath 후보와 연결 근거, 계층별 타임라인을 확인합니다. 직접 들어오면 현재 범위에서 가장 느린 요청부터 보여 줍니다. 요청 목록은 Choose another request에서 펼칩니다.
- **Compare**: Keep current as baseline을 누른 뒤 다음 기록 또는 세션을 열어 결과를 비교합니다. 기준은 앱이 실행된 동안 메모리에 유지됩니다. 비교 전에 요청 필터를 해제해야 합니다. 같은 workload·비슷한 기록 구간인지 확인하고 결과를 해석합니다.
- **Diagnostics**: 수집 상태·손실·지원하지 않는 측정·오류를 확인합니다. 연결된 폰 기능 점검과 진단 번들 내보내기를 제공합니다.

## 선택 Summary 읽기

상단은 선택 I/O 개수와 End−Start, 세션 기준 시간 구간입니다. **Volume & throughput**은 Read/Write 건수·용량·MiB/s를, **Total latency**는 P50/P90/P95/P99/Max를 같은 열에서 비교합니다. 미측정 값은 —로 표시합니다. 단위는 각 값 또는 행에 명시합니다. 자세한 정의와 절대 timestamp는 Definitions & timestamps에서 펼칩니다.

**Files** 탭은 경로 후보·device/inode·신뢰도·접근 프로세스를, **Processes** 탭은 process/PID/TID·I/O량·파일 근거를 보여 줍니다. 각 탭은 독립적으로 스크롤합니다. Summary 아래쪽에서 접근 패턴과 Read/Write Chunk 파이차트를 확인합니다. **Zoom selection / Back / Clear**는 스크롤과 별도로 패널 상단에 유지됩니다.

파일 이름처럼 범례가 많거나 긴 분류는 그래프를 가리지 않도록 Plot legend가 기본으로 꺼집니다. 전체 항목명·색상은 Colors에 남고, Plot legend를 켜면 그래프 위 범례를 다시 볼 수 있습니다.
