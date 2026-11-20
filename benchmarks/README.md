# x64dbgSQL와 x64dbg-MCP 비교

Windows에서 동일한 입력 파일과 동일한 x64dbg 빌드를 사용합니다. SQL은 배포 ZIP의 `x64dbgsql.exe`와 플러그인을, MCP는 공식 x64dbg-MCP ZIP의 플러그인을 사용합니다. `prepare.py`는 ZIP 해시를 확인하고 각 참가자 전용 폴더에 파일과 설정을 복제합니다. 디버깅 대상을 실행하지 않고 두 플러그인의 연결을 확인합니다.
Python 3.11 이상이 필요합니다.

```powershell
python -B benchmarks/prepare.py --sample SAMPLE.exe --sql-zip SQL.zip --sql-sha256 SQL_SHA256 --mcp-zip MCP.zip --mcp-sha256 MCP_SHA256 --debugger X64DBG_RELEASE_DIR --output RUN_DIR
```

- 양쪽에 같은 모델과 동일한 과제를 사용합니다. 새 에이전트에 자기 경로와 인터페이스만 전달합니다. 이전 풀이, 상대 에이전트의 자료 및 다른 분석 인터페이스 사용을 제한합니다.
- 각 에이전트의 첫 도구 작업에서 `python -B benchmarks/measure.py start RUN_DIR/sql` 또는 `RUN_DIR/mcp`를 실행합니다. 설치·연결 확인은 이 전에 마칩니다. 첫 샘플 단서는 `clue`로 기록합니다.
- `Trial.sql`, `Trial.sql_session`, `Trial.mcp_session`에서 호출의 시작, 응답 파싱 완료, 작업 이름을 `requests.jsonl`에 기록합니다. 실패한 요청도 집계합니다. SQL은 반복 조회에 동일한 `sql_session`을 유지합니다. DB 연동은 배포판의 공개 인터페이스를 사용합니다.
- 양쪽 모두 `Trial.verify`로 원본과 같은 SHA-256을 지닌 복사본을 정상 실행해 성공·실패 대조 입력의 출력과 종료 코드를 확인합니다. 검증 스크립트의 입력값은 측정 로그에 기록하지 않습니다. 중단되면 `stop`으로 종료 시점을 남깁니다.
- `python -B benchmarks/measure.py report RUN_DIR`은 성공 검증, 중단, 보고 시각 순으로 종료 기준을 선택하고 `cutoff`에 사용한 기준을 기록합니다. 시작 표식이 없으면 소요 시간은 `null`입니다.
- 시작 전 `python -B benchmarks/memory.py sample RUN_DIR`로 도구 프로세스 메모리를 250ms 간격으로 기록합니다. 참가자는 `Trial.track`으로 자신이 시작한 디버거와 분석기 PID를 등록합니다. 상주 SQL CLI는 자동 등록됩니다. 실험이 끝나면 `RUN_DIR/memory-stop` 파일을 만들고 `memory.py report RUN_DIR`로 같은 시점의 합산 피크를 확인합니다. 사설 커밋과 작업 집합을 각각 보고합니다.

## 보고서 해석

- `client_observed_seconds_by_api`는 측정 구간 안에서 시작하고 끝난 요청 시간의 합계입니다. `client_active_seconds`와 `client_active_seconds_by_api`는 요청 구간의 합집합 길이입니다. Windows에서 같은 시스템의 `perf_counter_ns` 값을 사용하며, 구간 안에서 시작해 종료 기준 이후에 끝난 요청은 종료 기준까지의 시간만 더합니다. 전체 풀이 시간에는 에이전트의 판단과 로컬 계산도 포함됩니다.
- `request_latency_by_operation`의 p50·p95는 파싱된 응답의 클라이언트 지연 시간(ms)에 최근접 순위법을 적용한 값입니다. 오류 응답도 표본과 오류 수에 포함됩니다. 시간 초과, 중단, 종료 기준을 넘긴 요청은 `censored_count`에 기록합니다. 알림은 따로 셉니다. 각 작업의 `sample_count`가 0이면 두 백분위수는 `null`입니다. 요청이 로그에 기록되기 전에 프로세스가 종료되면 집계할 수 없습니다. 기존 로그의 `received_response` 값으로 응답 유무를 추정하며, 상세 결과를 알 수 없는 건은 `unknown_outcome_count`에 표시합니다.
- 메모리의 `samples`는 측정값을 얻은 시점 수입니다. `peak_combined_working`과 `peak_combined_private`는 각 시점에서 관측된 PID를 한 번씩 합산한 뒤 구한 피크(바이트)입니다. `peak_by_role`은 역할 내 개별 프로세스의 최댓값입니다. 로그가 없거나 해당 구간에서 채집한 값이 없으면 합산 피크는 `null`입니다. `unsampled_processes`는 등록 목록에서 측정 구간 내 관측값이 없는 PID와 역할을 보여 줍니다. 짧게 실행되는 프로세스나 250ms 간격 사이에 발생한 피크는 샘플링에서 빠질 수 있습니다.
- 한 번의 비교 결과는 해당 실행에 대한 관측입니다. 반복 비교에서는 이전 풀이를 모르는 에이전트와 별개의 샘플을 사용하고, 각 도구의 실행 순서를 교차하며 중앙값과 산포를 비교합니다. 모델, 요청 제한 시간, 분석기 버전, 시작 시점의 분석기 상태를 기록해 반복 실행 조건을 재현할 수 있게 합니다.

보고서 집계를 확인하는 테스트는 합성 로그를 사용합니다.

```powershell
python -B -m unittest discover -s benchmarks -v
```

```python
from measure import Trial

trial = Trial(lane)
with trial.sql_session('--session', session_id) as client:
    client.initialize()
    result = client.tool('x64dbgsql_query', sql='SELECT * FROM stop_context')
```
