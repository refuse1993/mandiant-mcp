# Mandiant MCP 서버 설치 및 실행 가이드

이 가이드는 Mandiant API v4와 연동되는 MCP(Model Context Protocol) 서버를 설치하고 Claude Desktop에 연동하는 방법을 설명합니다.

## 1. 사전 요구사항

- Python 3.8 이상
- Mandiant API 키 (https://www.mandiant.com/advantage 에서 가입 필요)
- Claude Desktop 앱 (최신 버전)

## 2. 가상환경 설정

```bash
# 가상환경 생성
python -m venv mandiant-mcp-env

# 가상환경 활성화 (Windows)
.\mandiant-mcp-env\Scripts\activate

# 가상환경 활성화 (macOS/Linux)
source mandiant-mcp-env/bin/activate

# 필요한 패키지 설치
pip install mcp requests httpx python-dotenv
```

## 3. 프로젝트 파일 준비

1. `mandiant_server.py` 파일 생성 (제공된 코드를 복사)
2. `.env` 파일 생성 및 API 키 설정:

```
MANDIANT_KEY_ID=your_api_key_here
MANDIANT_KEY_SECRET=your_api_key_here
```

## 4. 서버 테스트

```bash
# 가상환경이 활성화된 상태에서:
python mandiant_server.py
```

오류 없이 실행되면 Claude Desktop 연동 준비가 완료된 것입니다.

## 5. Claude Desktop 연동

1. Claude Desktop 앱 열기
2. 메뉴에서 "Settings..." 선택
3. "Developer" 섹션 클릭
4. "Edit Config" 버튼 클릭

다음 경로에 위치한 구성 파일이 열립니다:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

5. 구성 파일을 다음과 같이 업데이트:

```json
{
  "mcpServers": {
    "mandiant": {
      "command": "/실제/경로/mandiant-mcp-env/bin/python",
      "args": [
        "/실제/경로/mandiant_server.py"
      ],
      "env": {
        "MANDIANT_KEY_ID":"your_api_key_here",
        "MANDIANT_KEY_SECRET":"your_api_key_here"
      }
    }
  }
}
```

주의: 
- 실제 Python 가상환경 경로로 `/실제/경로` 부분을 교체해야 합니다.
- Windows에서는 경로 구분자로 `\\`를 사용하거나 `/`를 사용해도 됩니다.
- API 키를 직접 입력하거나, `.env` 파일에만 저장하는 방식 중 선택할 수 있습니다.

## 6. Claude Desktop 재시작

Claude Desktop 앱을 완전히 종료한 후 다시 시작합니다.

## 7. MCP 서버 확인

Claude Desktop이 다시 시작되면 입력창 오른쪽 하단에 해머 아이콘이 표시됩니다. 이 아이콘을 클릭하면 연동된 Mandiant 서버와 사용 가능한 기능이 표시됩니다.

## 8. 사용 예시

Claude에게 다음과 같은 질문을 해보세요:

- "최근 발견된 취약점에 대해 알려줄래?"
- "APT29 위협 그룹에 대해 조사해 줄 수 있니?"
- "이 IP 주소 (예: 93.184.216.34)를 분석해 줄 수 있어?"
- "최근 Mandiant 인텔리전스 리포트를 보여줘"

## 문제 해결

### MCP 서버가 Claude Desktop에 표시되지 않는 경우:

1. 구성 파일의 경로가 정확한지 확인하세요.
2. 가상환경이 올바르게 설정되었는지 확인하세요.
3. Claude Desktop 로그 확인:
   - macOS: `~/Library/Logs/Claude/main.log`
   - Windows: `%APPDATA%\Claude\logs\main.log`

### API 요청 오류:

1. API 키가 올바른지 확인하세요.
2. 인터넷 연결을 확인하세요.
3. Mandiant API 사용 권한과 할당량을 확인하세요.


# Mandiant MCP 서버 사용 예제

Mandiant MCP 서버를 Claude와 함께 사용하는 다양한 예제를 소개합니다.

## 기본 기능 사용하기

### 위협 액터 정보 조회

Claude에게 다음과 같이 물어보세요:

> "APT29 그룹에 대한 정보를 알려줄 수 있어?"

Claude는 Mandiant API를 통해 APT29 관련 정보를 검색하고 다음과 같은 정보를 제공할 것입니다:
- 그룹 설명
- 모티베이션
- 별칭
- 관련 활동

### 취약점 분석

최근 CVE에 대한 정보를 얻으려면:

> "CVE-2023-1234에 대해 알려줄 수 있어? 이 취약점이 얼마나 위험한지 평가해줘."

Claude는 취약점 세부 정보를 조회하고:
- 취약점 설명
- CVSS 점수
- 영향을 받는 제품
- 완화 방법
- 위험 수준 평가

### IoC 분석

의심스러운 IP나 도메인을 분석하려면:

> "이 IP 주소 185.130.44.108이 악성인지 분석해줄 수 있어?"

Claude는 다음 정보를 제공합니다:
- 관련 악성코드
- 연관된 위협 액터
- 관련 리포트

### 검색 기능 활용

특정 주제에 대한 정보를 검색하려면:

> "랜섬웨어 위협 그룹에 대한 최신 정보를 검색해줘."

Claude는 관련 검색 결과를 제공합니다.

## 고급 사용 사례

### 위협 조사 프롬프트 사용

특정 위협에 대한 체계적인 조사가 필요하면:

> "/investigate_threat 명령어를 사용해서 Lazarus Group을 조사해줘."

Claude는 조사 프롬프트를 활용하여 체계적인 분석을 제공합니다:
1. 위협 액터 정보 검색
2. 관련 IoC 식별
3. TTPs(전술, 기법, 절차) 요약
4. 방어 권장사항

### 취약점 평가 프롬프트 사용

특정 CVE에 대한 심층 평가:

> "/assess_vulnerability 명령어로 CVE-2023-12345를 평가해줘."

Claude는 취약점에 대한 종합적인 평가를 제공합니다:
1. 취약점 상세 정보
2. 잠재적 영향
3. 영향 받는 시스템
4. 완화 전략
5. 현재 활발히 악용되고 있는지 여부

### 복합 분석 활용

여러 기능을 연계하여 심층 분석을 수행할 수 있습니다:

> "최근 발생한 의료 기관 대상 사이버 공격에 대해 분석해줘. 관련 위협 액터, 사용된 취약점, 그리고 방어 방법을 포함해서 알려줘."

Claude는 다음 작업을 수행합니다:
1. 관련 위협 검색
2. 의료 기관 관련 취약점 확인
3. 연관된 위협 액터 분석
4. 최근 보고서 참조
5. 종합 방어 권장사항 제시

## 팁과 트릭

1. **구체적인 질문하기**: "최근 취약점"보다는 "최근 발견된 원격 코드 실행 취약점"과 같이 구체적으로 질문하면 더 정확한 결과를 얻을 수 있습니다.

2. **컨텍스트 유지하기**: Claude는 대화 컨텍스트를 유지하므로, "이 그룹의 주요 표적은 뭐야?"와 같은 후속 질문을 자연스럽게 할 수 있습니다.

3. **다중 질문 조합하기**: "최근 발견된 Log4j 취약점과 이를 악용하는 위협 그룹에 대해 알려줘"와 같이 여러 주제를 하나의 질문으로 조합할 수 있습니다.

4. **특정 도구 지정하기**: 특정 분석이 필요한 경우 "analyze_ioc 도구를 사용해서 이 도메인을 분석해줘"와 같이 직접 도구를 지정할 수 있습니다.

5. **결과 요약 요청하기**: 많은 정보가 있는 경우 "이 정보를 보안 팀을 위한 요약으로 정리해줄래?"와 같이 요청하면 Claude가 핵심 정보를 요약해줍니다.