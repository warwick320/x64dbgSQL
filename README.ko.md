# x64dbgSQL

x64dbg의 정지 상태, 레지스터, 모듈, 디스어셈블리와 이벤트를 SQL로 조회합니다. 터미널, 스크립트, 로컬 MCP 클라이언트에서 사용할 수 있습니다.

[다운로드](https://github.com/warwick320/x64dbgSQL/releases) · [상세 사용법](docs/usage.md) · [English](README.md)

## 설치

1. x64 Windows에 [x64dbg 배포 파일](https://github.com/x64dbg/x64dbg/releases/tag/2026.05.27)을 쓰기 가능한 폴더에 풉니다.
2. 디버거와 x64dbgSQL 클라이언트를 닫고 [Releases](https://github.com/warwick320/x64dbgSQL/releases)의 **x64dbgsql-setup.exe**를 실행합니다.
3. `x64`와 `x32`가 들어 있는 상위 폴더를 선택합니다. 보통 `release` 폴더입니다. x64dbg나 x32dbg를 열어 대상 프로그램을 일시 정지합니다.

무설치로 쓰려면 **x64dbgsql-windows.zip**을 같은 폴더에 풉니다. 업데이트할 때는 CLI와 플러그인을 함께 교체합니다. 설치 프로그램으로 설치했다면 같은 경로에 다시 설치해 업데이트하거나, Windows **설정 → 앱 → 설치된 앱**에서 제거할 수 있습니다. 무설치 버전은 x64dbgSQL 실행 파일 두 개와 설치한 플러그인 파일을 직접 삭제합니다.

```powershell
.\x64dbgsql.exe sessions
.\x64dbgsql.exe query -q 'SELECT * FROM stop_context'
.\x64dbgsql.exe query -q 'SELECT d.addr, d.text FROM session s JOIN disassembly(s.ip, 8) d'
```

세션이 여러 개면 `--session ID`를 지정합니다. `schema --offline`으로 디버거 연결 없이 테이블을 확인할 수 있습니다.

## 창 없이 실행하기

터미널에서는 **x64dbgsql.exe**를, MCP나 자동화에서는 **x64dbgsql-headless.exe**를 사용합니다. MCP는 로컬 stdio 방식으로 실행 파일 경로와 `["mcp", "--compact"]` 인자를 설정합니다. 디버거 창도 없이 실행하려면 x64dbg 배포판의 **headless.exe**를 사용합니다. [헤드리스 실행 예제](docs/usage.md#headless-sessions)에 콘솔 없이 디버거를 시작하고 결과를 받는 방법이 있습니다. 디버깅 대상 자체의 창은 대상 프로그램에 따라 달라집니다.

설치도 창 없이 진행하려면 설치 프로그램에 `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /DIR="C:\Tools\x64dbg\release"`를 전달합니다. [설치·제거 명령](docs/usage.md#unattended-installation)을 참고하세요.

## 개발과 배포

[빌드 및 테스트](README.md#build-from-source) 절차로 x64·x86을 모두 빌드합니다. `./cmake/PackageWindows.ps1`로 Windows ZIP, 소스 ZIP, SHA-256 목록을 만듭니다. `-InnoCompiler <ISCC.exe 경로>`를 추가하면 설치 프로그램도 생성됩니다. [정적 분석 연동과 배포 안내](docs/usage.md)를 참고하세요.

[MIT 라이선스](LICENSE) · [서드파티 고지](licenses/README.md)
