---
revision: 1
level: L2
route: REQUIREMENTS_FIRST
execution_mode: EPHEMERAL
confirmation: CONFIRMED-AUTO
lifecycle: CONFIRMED
---

# 분석 UI 가독성·조작성 개선

[User] expert-ui-design 4.6.0으로 데이터 읽기, 조작 방법 발견, 조작성을 개선한다. 범위 안의 가역적인 UI 변경을 요청한 현재 발화가 구현 근거다.

[Repo evidence] Rust/egui 0.36.1, English UI, System/Light/Dark/HighContrast와 28px 제어 높이가 기존 권위다. filter_ui의 Clear filters는 접힌 영역 안에 있고 활성 표시는 구체적인 조건을 설명하지 않는다. Completed block I/O의 헤더는 가상화된 첫 행이라 수직 스크롤 때 사라지고 숫자/텍스트를 같은 기본 정렬로 표시한다. Open session은 메뉴 내부에 있어 폰 없이 분석을 시작하는 경로가 눈에 띄지 않는다.

## Page Contract

- 주 작업: operate/understand — 저장 세션 열기 또는 수집 → 조건으로 좁히기 → 그래프 선택 → 요청 근거.
- Auto + existing-product 방향. 새 테마/웹 UI/색상 인코딩을 만들지 않고 기존 분석 화면의 정보 위계를 강화한다.
- REQ-1: 고급 필터를 열지 않아도 활성 조건과 전체 해제를 발견한다. reset은 숫자 입력의 delayed commit을 막는 epoch 처리와 기존 invalidate 경로를 유지한다.
- REQ-2: 요청 테이블은 수직 스크롤 중 헤더를 유지하고 헤더·본문은 같은 가로 스크롤과 열 폭을 사용한다. 수치/식별자는 고정폭 글꼴, 수치는 오른쪽 정렬; 전체 값은 hover로 유지한다. 행 가상화·newest-first·Open I/O 키보드 동작을 보존한다.
- REQ-3: 상단에 저장 세션 열기, 연결 없는 시작 버튼의 이유, Explore의 선택/확대 의도를 표시한다. 색만으로 모드를 표현하지 않는다.
- REQ-4: 비어 있는 필터 결과에는 복구 동작을 안내한다. 수집 중/분석 중/미측정/불확실한 파일 연결을 데이터 없음이나 성능 결론으로 바꾸지 않는다.
- NFR: 렌더 프레임에 전체 데이터 재집계 추가 금지; 테이블은 visible rows만 분석한다. 기존 영문/테마/측정 단위/프로토콜/수집/수출 의미 보존.

## 계약과 검증

필터는 표시 코호트만 변경하고 원본을 지우지 않는다. Clear selection과 Clear filters는 서로 다른 기존 동작이다. 저장 세션 열기는 수집 중 비활성화한다. 새 도메인/서비스/데이터 schema 모델은 N/A — 표현과 기존 UI 상태 경계만 수정한다. 관측성은 기존 RenderQa regions를 재사용하며 기기 경로나 원본을 새 로그로 전송하지 않는다.

TSK-1/TST-1: 접힌 필터의 reset 버튼으로 활성 PID 코호트를 전체로 복원하는 egui 입력 회귀; 원본은 버튼 region 부재로 실패 예상.
TSK-2/TST-2: 테이블의 열 경계·정렬 및 수직 스크롤 후 헤더 유지 egui 페인트 검사; 기존 Open I/O keyboard 회귀 유지.
TSK-3: 헤더·모드 안내와 복구 상태 구현, 관련 소스 검토.
검증 명령: cargo +1.98.0 test -p android-ebpf-studio --features gui; cargo +1.98.0 check -p android-ebpf-studio --features gui. 현재 로컬에는 cargo/rustc가 없어 실행 환경 BLOCKED. 실제 RED를 얻기 전 결과를 TDD 성공으로 기록하지 않는다. 변경은 검증 상태를 공개한 검토 브랜치/PR로 보존한다.

원격 CI 결과와 네이티브 화면 확인 전 SATISFIED를 주장하지 않는다. 목표 화면은 1600×1000 및 1000×800, 정상/0결과/선택/긴 경로, Light/Dark/HighContrast. 브라우저 HTML 목업은 네이티브 앱 검증을 대신하지 않는다. 배포·릴리스는 범위 밖이다.
