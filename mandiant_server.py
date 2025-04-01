#!/usr/bin/env python3
# mandiant_server.py

import os
import json
import httpx
import sys
from typing import Dict, List, Optional, Any, Union
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from dataclasses import dataclass
from dotenv import load_dotenv

from mcp.server.fastmcp import FastMCP, Context, Image

# 디버깅을 위한 출력
print("Starting Mandiant MCP Server...", file=sys.stderr)

# .env 파일 로드
load_dotenv()

# Mandiant API 설정
MANDIANT_KEY_ID = os.getenv("MANDIANT_KEY_ID")
MANDIANT_KEY_SECRET = os.getenv("MANDIANT_KEY_SECRET")

if not MANDIANT_KEY_ID or not MANDIANT_KEY_SECRET:
    print("Warning: MANDIANT_KEY_ID or MANDIANT_KEY_SECRET not found in environment variables", file=sys.stderr)

MANDIANT_BASE_URL = "https://api.intelligence.mandiant.com"

@dataclass
class AppContext:
    api_client: httpx.AsyncClient

@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """애플리케이션 수명 주기 관리 및 API 클라이언트 초기화"""
    print("Initializing API client...", file=sys.stderr)
    
    # API 클라이언트 초기화
    headers = {
        "X-App-Name": "MCP-Mandiant-Server"
    }

    auth = (MANDIANT_KEY_ID, MANDIANT_KEY_SECRET)

    async with httpx.AsyncClient(
        base_url=MANDIANT_BASE_URL, 
        headers=headers,
        auth=auth  # 기본 인증(Basic Authentication)으로 변경
    ) as client:
        print("API client initialized", file=sys.stderr)
        yield AppContext(api_client=client)
    
    print("API client closed", file=sys.stderr)

# MCP 서버 초기화
mcp = FastMCP(
    "Mandiant Intelligence", 
    lifespan=app_lifespan,
    dependencies=["httpx", "python-dotenv"]
)

# 위협 액터 관련 도구
@mcp.tool()
async def get_threat_actors(ctx: Context) -> str:
    """Mandiant에서 추적 중인 위협 액터 목록을 가져옵니다."""
    client = ctx.request_context.lifespan_context.api_client
    
    try:
        response = await client.get("/v4/actor")
        print(f"API Response: {response.status_code}", file=sys.stderr)
        
        if not response.is_success:
            data = response.json() if response.headers.get('content-type') == 'application/json' else {}
            error_msg = data.get('message', f"Unknown error (Status: {response.status_code})")
            return f"Error fetching threat actors: {error_msg}"
        
        data = response.json()
        actors = data.get("actors", [])
        result = "# Mandiant 위협 액터 목록\n\n"
        
        for actor in actors:
            result += f"- **{actor.get('name')}** ({actor.get('id')})\n"
            if actor.get('description'):
                result += f"  - {actor.get('description')[:150]}...\n"
        
        return result
    except Exception as e:
        print(f"Exception in get_threat_actors: {str(e)}", file=sys.stderr)
        return f"Error fetching threat actors: {str(e)}"

@mcp.tool()
async def get_actor_details(actor_id: str, ctx: Context) -> str:
    """특정 위협 액터에 대한 상세 정보를 가져옵니다."""
    client = ctx.request_context.lifespan_context.api_client
    
    try:
        response = await client.get(f"/v4/actor/{actor_id}")
        print(f"API Response: {response.status_code}", file=sys.stderr)
        
        if not response.is_success:
            data = response.json() if response.headers.get('content-type') == 'application/json' else {}
            error_msg = data.get('message', f"Unknown error (Status: {response.status_code})")
            return f"Error fetching actor details: {error_msg}"
        
        actor = response.json()
        
        result = f"# {actor.get('name', 'Unknown Actor')}\n\n"
        result += f"**ID:** {actor.get('id')}\n\n"
        
        if actor.get('description'):
            result += f"**Description:** {actor.get('description')}\n\n"
        
        if actor.get('motivations'):
            result += "**Motivations:**\n"
            for motivation in actor.get('motivations', []):
                result += f"- {motivation}\n"
            result += "\n"
        
        if actor.get('aliases'):
            result += "**Also known as:**\n"
            for alias in actor.get('aliases', []):
                result += f"- {alias}\n"
            result += "\n"
        
        # 추가 정보 섹션
        result += "## Additional Information\n\n"
        result += f"**Associated Reports:** Try `get_actor_reports(\"{actor_id}\")`\n"
        result += f"**Attack Patterns:** Try `get_actor_attack_patterns(\"{actor_id}\")`\n"
        result += f"**Associated Indicators:** Try `get_actor_indicators(\"{actor_id}\")`\n"
        
        return result
    except Exception as e:
        print(f"Exception in get_actor_details: {str(e)}", file=sys.stderr)
        return f"Error fetching actor details: {str(e)}"

@mcp.tool()
async def get_actor_reports(actor_id: str, ctx: Context) -> str:
    """특정 위협 액터와 관련된 보고서를 가져옵니다."""
    client = ctx.request_context.lifespan_context.api_client
    
    try:
        response = await client.get(f"/v4/actor/{actor_id}/reports")
        print(f"API Response: {response.status_code}", file=sys.stderr)
        
        if not response.is_success:
            data = response.json() if response.headers.get('content-type') == 'application/json' else {}
            error_msg = data.get('message', f"Unknown error (Status: {response.status_code})")
            return f"Error fetching actor reports: {error_msg}"
        
        data = response.json()
        reports = data.get("reports", [])
        
        result = f"# Reports for {actor_id}\n\n"
        if not reports:
            return result + "No reports found for this actor."
        
        for report in reports:
            result += f"## {report.get('title')}\n"
            result += f"**ID:** {report.get('id')}\n"
            result += f"**Published:** {report.get('published_date')}\n"
            if report.get('summary'):
                result += f"\n{report.get('summary')[:200]}...\n\n"
            result += "\n"
        
        return result
    except Exception as e:
        print(f"Exception in get_actor_reports: {str(e)}", file=sys.stderr)
        return f"Error fetching actor reports: {str(e)}"

@mcp.tool()
async def get_actor_indicators(actor_id: str, ctx: Context) -> str:
    """특정 위협 액터와 관련된 지표(IOC)를 가져옵니다."""
    client = ctx.request_context.lifespan_context.api_client
    
    try:
        response = await client.get(f"/v4/actor/{actor_id}/indicators")
        print(f"API Response: {response.status_code}", file=sys.stderr)
        
        if not response.is_success:
            data = response.json() if response.headers.get('content-type') == 'application/json' else {}
            error_msg = data.get('message', f"Unknown error (Status: {response.status_code})")
            return f"Error fetching actor indicators: {error_msg}"
        
        data = response.json()
        indicators = data.get("indicators", [])
        
        result = f"# Indicators for {actor_id}\n\n"
        if not indicators:
            return result + "No indicators found for this actor."
        
        # 지표 타입별로 분류
        indicator_by_type = {}
        for indicator in indicators:
            indicator_type = indicator.get('type', 'unknown')
            if indicator_type not in indicator_by_type:
                indicator_by_type[indicator_type] = []
            indicator_by_type[indicator_type].append(indicator)
        
        # 타입별로 출력
        for indicator_type, type_indicators in indicator_by_type.items():
            result += f"## {indicator_type.upper()}\n\n"
            for indicator in type_indicators[:10]:  # 각 타입당 최대 10개만 표시
                result += f"- **{indicator.get('value')}**\n"
                if indicator.get('last_seen'):
                    result += f"  - Last seen: {indicator.get('last_seen')}\n"
            
            if len(type_indicators) > 10:
                result += f"\n*...and {len(type_indicators) - 10} more {indicator_type} indicators*\n"
            result += "\n"
        
        return result
    except Exception as e:
        print(f"Exception in get_actor_indicators: {str(e)}", file=sys.stderr)
        return f"Error fetching actor indicators: {str(e)}"

@mcp.tool()
async def get_actor_attack_patterns(actor_id: str, ctx: Context) -> str:
    """특정 위협 액터와 관련된 MITRE ATT&CK 패턴을 가져옵니다."""
    client = ctx.request_context.lifespan_context.api_client
    
    try:
        response = await client.get(f"/v4/actor/{actor_id}/attack-pattern")
        print(f"API Response: {response.status_code}", file=sys.stderr)
        
        if not response.is_success:
            data = response.json() if response.headers.get('content-type') == 'application/json' else {}
            error_msg = data.get('message', f"Unknown error (Status: {response.status_code})")
            return f"Error fetching actor attack patterns: {error_msg}"
        
        data = response.json()
        patterns = data.get("attack-patterns", [])
        
        result = f"# MITRE ATT&CK Patterns for {actor_id}\n\n"
        if not patterns:
            return result + "No attack patterns found for this actor."
        
        # 전술별로 분류
        patterns_by_tactic = {}
        for pattern in patterns:
            for tactic in pattern.get('tactics', []):
                tactic_name = tactic.get('name', 'unknown')
                if tactic_name not in patterns_by_tactic:
                    patterns_by_tactic[tactic_name] = []
                patterns_by_tactic[tactic_name].append(pattern)
        
        # 전술별로 출력
        for tactic_name, tactic_patterns in patterns_by_tactic.items():
            result += f"## {tactic_name}\n\n"
            for pattern in tactic_patterns:
                result += f"- **{pattern.get('name')}** ({pattern.get('id')})\n"
                if pattern.get('description'):
                    result += f"  - {pattern.get('description')[:150]}...\n"
            result += "\n"
        
        return result
    except Exception as e:
        print(f"Exception in get_actor_attack_patterns: {str(e)}", file=sys.stderr)
        return f"Error fetching actor attack patterns: {str(e)}"

# 취약점 관련 도구
@mcp.tool()
async def get_vulnerabilities(ctx: Context) -> str:
    """최신 취약점 정보를 가져옵니다."""
    client = ctx.request_context.lifespan_context.api_client
    
    try:
        response = await client.get("/v4/vulnerability")
        print(f"API Response: {response.status_code}", file=sys.stderr)
        
        if not response.is_success:
            data = response.json() if response.headers.get('content-type') == 'application/json' else {}
            error_msg = data.get('message', f"Unknown error (Status: {response.status_code})")
            return f"Error fetching vulnerabilities: {error_msg}"
        
        data = response.json()
        vulns = data.get("vulnerabilities", [])
        
        result = "# 최신 취약점 목록\n\n"
        for vuln in vulns:
            result += f"- **{vuln.get('cve_id')}** - {vuln.get('name', 'No name')}\n"
            if vuln.get('description'):
                result += f"  - {vuln.get('description')[:150]}...\n"
            result += f"  - CVSS Score: {vuln.get('cvss_score')}\n\n"
        
        return result
    except Exception as e:
        print(f"Exception in get_vulnerabilities: {str(e)}", file=sys.stderr)
        return f"Error fetching vulnerabilities: {str(e)}"

@mcp.tool()
async def get_vulnerability_details(cve_id: str, ctx: Context) -> str:
    """특정 CVE에 대한 상세 정보를 가져옵니다."""
    client = ctx.request_context.lifespan_context.api_client
    
    try:
        response = await client.get(f"/v4/vulnerability/{cve_id}")
        print(f"API Response: {response.status_code}", file=sys.stderr)
        
        if not response.is_success:
            data = response.json() if response.headers.get('content-type') == 'application/json' else {}
            error_msg = data.get('message', f"Unknown error (Status: {response.status_code})")
            return f"Error fetching CVE details: {error_msg}"
        
        vuln = response.json()
        
        result = f"# {vuln.get('cve_id')} - {vuln.get('name', 'Unknown Vulnerability')}\n\n"
        
        if vuln.get('description'):
            result += f"**Description:** {vuln.get('description')}\n\n"
        
        result += f"**CVSS Score:** {vuln.get('cvss_score')}\n"
        result += f"**Published Date:** {vuln.get('published_date')}\n"
        
        if vuln.get('affected_products'):
            result += "\n**Affected Products:**\n"
            for product in vuln.get('affected_products', []):
                result += f"- {product.get('name')}\n"
        
        if vuln.get('mitigation'):
            result += f"\n**Mitigation:**\n{vuln.get('mitigation')}\n"
        
        # 추가 정보 섹션
        result += "\n## Additional Information\n\n"
        result += f"**Related Actors:** Try `get_vulnerability_actors(\"{cve_id}\")`\n"
        result += f"**Related Malware:** Try `get_vulnerability_malware(\"{cve_id}\")`\n"
        
        return result
    except Exception as e:
        print(f"Exception in get_vulnerability_details: {str(e)}", file=sys.stderr)
        return f"Error fetching CVE details: {str(e)}"

@mcp.tool()
async def get_vulnerability_actors(cve_id: str, ctx: Context) -> str:
    """특정 취약점과 관련된 위협 액터를 가져옵니다."""
    client = ctx.request_context.lifespan_context.api_client
    
    try:
        response = await client.get(f"/v4/vulnerability/{cve_id}/actors")
        print(f"API Response: {response.status_code}", file=sys.stderr)
        
        if not response.is_success:
            data = response.json() if response.headers.get('content-type') == 'application/json' else {}
            error_msg = data.get('message', f"Unknown error (Status: {response.status_code})")
            return f"Error fetching vulnerability actors: {error_msg}"
        
        data = response.json()
        actors = data.get("actors", [])
        
        result = f"# Threat Actors Related to {cve_id}\n\n"
        if not actors:
            return result + "No threat actors found for this vulnerability."
        
        for actor in actors:
            result += f"- **{actor.get('name')}** ({actor.get('id')})\n"
            if actor.get('description'):
                result += f"  - {actor.get('description')[:150]}...\n"
        
        return result
    except Exception as e:
        print(f"Exception in get_vulnerability_actors: {str(e)}", file=sys.stderr)
        return f"Error fetching vulnerability actors: {str(e)}"

@mcp.tool()
async def get_vulnerability_malware(cve_id: str, ctx: Context) -> str:
    """특정 취약점과 관련된 악성코드를 가져옵니다."""
    client = ctx.request_context.lifespan_context.api_client
    
    try:
        response = await client.get(f"/v4/vulnerability/{cve_id}/malware")
        print(f"API Response: {response.status_code}", file=sys.stderr)
        
        if not response.is_success:
            data = response.json() if response.headers.get('content-type') == 'application/json' else {}
            error_msg = data.get('message', f"Unknown error (Status: {response.status_code})")
            return f"Error fetching vulnerability malware: {error_msg}"
        
        data = response.json()
        malware = data.get("malware", [])
        
        result = f"# Malware Related to {cve_id}\n\n"
        if not malware:
            return result + "No malware found for this vulnerability."
        
        for mal in malware:
            result += f"- **{mal.get('name')}** ({mal.get('id')})\n"
            if mal.get('description'):
                result += f"  - {mal.get('description')[:150]}...\n"
        
        return result
    except Exception as e:
        print(f"Exception in get_vulnerability_malware: {str(e)}", file=sys.stderr)
        return f"Error fetching vulnerability malware: {str(e)}"

# 악성코드 관련 도구
@mcp.tool()
async def get_malware_list(ctx: Context) -> str:
    """Mandiant에서 추적 중인 악성코드 패밀리 목록을 가져옵니다."""
    client = ctx.request_context.lifespan_context.api_client
    
    try:
        response = await client.get("/v4/malware")
        print(f"API Response: {response.status_code}", file=sys.stderr)
        
        if not response.is_success:
            data = response.json() if response.headers.get('content-type') == 'application/json' else {}
            error_msg = data.get('message', f"Unknown error (Status: {response.status_code})")
            return f"Error fetching malware list: {error_msg}"
        
        data = response.json()
        malware_list = data.get("malware", [])
        
        result = "# Mandiant 악성코드 패밀리 목록\n\n"
        for malware in malware_list:
            result += f"- **{malware.get('name')}** ({malware.get('id')})\n"
            if malware.get('description'):
                result += f"  - {malware.get('description')[:150]}...\n"
        
        return result
    except Exception as e:
        print(f"Exception in get_malware_list: {str(e)}", file=sys.stderr)
        return f"Error fetching malware list: {str(e)}"

@mcp.tool()
async def get_malware_details(malware_id: str, ctx: Context) -> str:
    """특정 악성코드 패밀리에 대한 상세 정보를 가져옵니다."""
    client = ctx.request_context.lifespan_context.api_client
    
    try:
        response = await client.get(f"/v4/malware/{malware_id}")
        print(f"API Response: {response.status_code}", file=sys.stderr)
        
        if not response.is_success:
            data = response.json() if response.headers.get('content-type') == 'application/json' else {}
            error_msg = data.get('message', f"Unknown error (Status: {response.status_code})")
            return f"Error fetching malware details: {error_msg}"
        
        malware = response.json()
        
        result = f"# {malware.get('name', 'Unknown Malware')}\n\n"
        result += f"**ID:** {malware.get('id')}\n\n"
        
        if malware.get('description'):
            result += f"**Description:** {malware.get('description')}\n\n"
        
        if malware.get('capabilities'):
            result += "**Capabilities:**\n"
            for capability in malware.get('capabilities', []):
                result += f"- {capability}\n"
            result += "\n"
        
        if malware.get('aliases'):
            result += "**Also known as:**\n"
            for alias in malware.get('aliases', []):
                result += f"- {alias}\n"
            result += "\n"
        
        # 추가 정보 섹션
        result += "## Additional Information\n\n"
        result += f"**Associated Reports:** Try `get_malware_reports(\"{malware_id}\")`\n"
        result += f"**Attack Patterns:** Try `get_malware_attack_patterns(\"{malware_id}\")`\n"
        result += f"**Associated Indicators:** Try `get_malware_indicators(\"{malware_id}\")`\n"
        
        return result
    except Exception as e:
        print(f"Exception in get_malware_details: {str(e)}", file=sys.stderr)
        return f"Error fetching malware details: {str(e)}"

@mcp.tool()
async def get_malware_indicators(malware_id: str, ctx: Context) -> str:
    """특정 악성코드와 관련된 지표(IOC)를 가져옵니다."""
    client = ctx.request_context.lifespan_context.api_client
    
    try:
        response = await client.get(f"/v4/malware/{malware_id}/indicators")
        print(f"API Response: {response.status_code}", file=sys.stderr)
        
        if not response.is_success:
            data = response.json() if response.headers.get('content-type') == 'application/json' else {}
            error_msg = data.get('message', f"Unknown error (Status: {response.status_code})")
            return f"Error fetching malware indicators: {error_msg}"
        
        data = response.json()
        indicators = data.get("indicators", [])
        
        result = f"# Indicators for {malware_id}\n\n"
        if not indicators:
            return result + "No indicators found for this malware."
        
        # 지표 타입별로 분류
        indicator_by_type = {}
        for indicator in indicators:
            indicator_type = indicator.get('type', 'unknown')
            if indicator_type not in indicator_by_type:
                indicator_by_type[indicator_type] = []
            indicator_by_type[indicator_type].append(indicator)
        
        # 타입별로 출력
        for indicator_type, type_indicators in indicator_by_type.items():
            result += f"## {indicator_type.upper()}\n\n"
            for indicator in type_indicators[:10]:  # 각 타입당 최대 10개만 표시
                result += f"- **{indicator.get('value')}**\n"
                if indicator.get('last_seen'):
                    result += f"  - Last seen: {indicator.get('last_seen')}\n"
            
            if len(type_indicators) > 10:
                result += f"\n*...and {len(type_indicators) - 10} more {indicator_type} indicators*\n"
            result += "\n"
        
        return result
    except Exception as e:
        print(f"Exception in get_malware_indicators: {str(e)}", file=sys.stderr)
        return f"Error fetching malware indicators: {str(e)}"

# 보고서 관련 도구
@mcp.tool()
async def get_recent_reports(ctx: Context, limit: int = 5) -> str:
    """최신 Mandiant 인텔리전스 리포트를 가져옵니다."""
    client = ctx.request_context.lifespan_context.api_client
    
    try:
        # 올바른 엔드포인트 사용: /v4/reports
        response = await client.get(f"/v4/reports?limit={min(limit, 10)}")
        print(f"API Response: {response.status_code}", file=sys.stderr)
        
        if not response.is_success:
            data = response.json() if response.headers.get('content-type') == 'application/json' else {}
            error_msg = data.get('message', f"Unknown error (Status: {response.status_code})")
            return f"Error fetching reports: {error_msg}"
        
        data = response.json()
        reports = data.get("reports", [])
        
        result = "# Recent Mandiant Intelligence Reports\n\n"
        if not reports:
            return result + "No reports found."
        
        for report in reports:
            result += f"## {report.get('title')}\n"
            result += f"**ID:** {report.get('id')}\n"
            result += f"**Published:** {report.get('published_date')}\n"
            if report.get('summary'):
                result += f"\n{report.get('summary')[:300]}...\n\n"
            result += "\n"
        
        return result
    except Exception as e:
        print(f"Exception in get_recent_reports: {str(e)}", file=sys.stderr)
        return f"Error fetching reports: {str(e)}"

@mcp.tool()
async def get_report_details(report_id: str, ctx: Context) -> str:
    """특정 보고서의 상세 정보를 가져옵니다."""
    client = ctx.request_context.lifespan_context.api_client
    
    try:
        response = await client.get(f"/v4/report/{report_id}")
        print(f"API Response: {response.status_code}", file=sys.stderr)
        
        if not response.is_success:
            data = response.json() if response.headers.get('content-type') == 'application/json' else {}
            error_msg = data.get('message', f"Unknown error (Status: {response.status_code})")
            return f"Error fetching report details: {error_msg}"
        
        report = response.json()
        
        result = f"# {report.get('title', 'Unknown Report')}\n\n"
        result += f"**ID:** {report.get('id')}\n"
        result += f"**Published:** {report.get('published_date', 'Unknown')}\n\n"
        
        if report.get('executive_summary'):
            result += f"## Executive Summary\n\n{report.get('executive_summary')}\n\n"
        
        if report.get('summary'):
            result += f"## Summary\n\n{report.get('summary')}\n\n"
        
        # 관련 지표 섹션
        result += "## Additional Information\n\n"
        result += f"**Associated Indicators:** Try `get_report_indicators(\"{report_id}\")`\n"
        
        return result
    except Exception as e:
        print(f"Exception in get_report_details: {str(e)}", file=sys.stderr)
        return f"Error fetching report details: {str(e)}"

@mcp.tool()
async def get_report_indicators(report_id: str, ctx: Context) -> str:
    """특정 보고서와 관련된 지표(IOC)를 가져옵니다."""
    client = ctx.request_context.lifespan_context.api_client
    
    try:
        response = await client.get(f"/v4/report/{report_id}/indicators")
        print(f"API Response: {response.status_code}", file=sys.stderr)
        
        if not response.is_success:
            data = response.json() if response.headers.get('content-type') == 'application/json' else {}
            error_msg = data.get('message', f"Unknown error (Status: {response.status_code})")
            return f"Error fetching report indicators: {error_msg}"
        
        data = response.json()
        indicators = data.get("indicators", [])
        
        result = f"# Indicators for Report {report_id}\n\n"
        if not indicators:
            return result + "No indicators found for this report."
        
# 지표 타입별로 분류
        indicator_by_type = {}
        for indicator in indicators:
            indicator_type = indicator.get('type', 'unknown')
            if indicator_type not in indicator_by_type:
                indicator_by_type[indicator_type] = []
            indicator_by_type[indicator_type].append(indicator)
        
        # 타입별로 출력
        for indicator_type, type_indicators in indicator_by_type.items():
            result += f"## {indicator_type.upper()}\n\n"
            for indicator in type_indicators[:10]:  # 각 타입당 최대 10개만 표시
                result += f"- **{indicator.get('value')}**\n"
                if indicator.get('last_seen'):
                    result += f"  - Last seen: {indicator.get('last_seen')}\n"
            
            if len(type_indicators) > 10:
                result += f"\n*...and {len(type_indicators) - 10} more {indicator_type} indicators*\n"
            result += "\n"
        
        return result
    except Exception as e:
        print(f"Exception in get_report_indicators: {str(e)}", file=sys.stderr)
        return f"Error fetching report indicators: {str(e)}"

# 지표(Indicator) 분석 도구
@mcp.tool()
async def analyze_ioc(indicator: str, ctx: Context) -> str:
    """표시기(IP, 도메인, 파일 해시 등)를 분석합니다."""
    client = ctx.request_context.lifespan_context.api_client
    
    try:
        # 표시기 유형 결정
        indicator_type = "unknown"
        if indicator.count(".") == 3 and all(part.isdigit() and 0 <= int(part) <= 255 for part in indicator.split(".")):
            indicator_type = "ip-address"
        elif "." in indicator and not any(c.isdigit() for c in indicator):
            indicator_type = "domain"
        elif len(indicator) == 32 or len(indicator) == 40 or len(indicator) == 64:
            indicator_type = "file-hash"
        
        print(f"Analyzing indicator: {indicator} (type: {indicator_type})", file=sys.stderr)
        response = await client.get(f"/v4/indicator/{indicator_type}/{indicator}")
        print(f"API Response: {response.status_code}", file=sys.stderr)
        
        if not response.is_success:
            data = response.json() if response.headers.get('content-type') == 'application/json' else {}
            error_msg = data.get('message', f"Unknown error (Status: {response.status_code})")
            return f"Error analyzing indicator: {error_msg}"
        
        data = response.json()
        
        output = f"# Analysis of {indicator} ({indicator_type})\n\n"
        
        if data.get('malware_families'):
            output += "## Associated Malware:\n"
            for malware in data.get('malware_families', []):
                output += f"- **{malware.get('name')}**\n"
                if malware.get('description'):
                    output += f"  - {malware.get('description')[:150]}...\n"
            output += "\n"
        
        if data.get('threat_actors'):
            output += "## Associated Threat Actors:\n"
            for actor in data.get('threat_actors', []):
                output += f"- **{actor.get('name')}**\n"
                if actor.get('description'):
                    output += f"  - {actor.get('description')[:150]}...\n"
            output += "\n"
        
        if data.get('reports'):
            output += "## Related Reports:\n"
            for report in data.get('reports', [])[:5]:
                output += f"- **{report.get('title')}** ({report.get('published_date')})\n"
                if report.get('summary'):
                    output += f"  - {report.get('summary')[:150]}...\n"
            
            if len(data.get('reports', [])) > 5:
                output += f"\n*...and {len(data.get('reports', [])) - 5} more reports*\n"
            output += "\n"
        
        # 추가 정보나 속성 표시
        if data.get('attributes'):
            output += "## Additional Attributes:\n"
            for attr_name, attr_value in data.get('attributes', {}).items():
                output += f"- **{attr_name}:** {attr_value}\n"
            output += "\n"
        
        return output
    except Exception as e:
        print(f"Exception in analyze_ioc: {str(e)}", file=sys.stderr)
        return f"Error analyzing indicator: {str(e)}"

# 검색 도구
@mcp.tool()
async def search_threats(query: str, ctx: Context) -> str:
    """Mandiant 인텔리전스에서 위협을 검색합니다."""
    client = ctx.request_context.lifespan_context.api_client
    
    try:
        payload = {
            "query": query,
            "limit": 10
        }
        
        response = await client.post("/v4/search", json=payload)
        print(f"API Response: {response.status_code}", file=sys.stderr)
        
        if not response.is_success:
            data = response.json() if response.headers.get('content-type') == 'application/json' else {}
            error_msg = data.get('message', f"Unknown error (Status: {response.status_code})")
            return f"Error searching threats: {error_msg}"
        
        data = response.json()
        results = data.get("results", [])
        
        if not results:
            return f"No results found for query: '{query}'"
        
        output = f"# Search Results for '{query}'\n\n"
        
        # 결과 타입별로 분류
        results_by_type = {}
        for result in results:
            result_type = result.get('type', 'unknown')
            if result_type not in results_by_type:
                results_by_type[result_type] = []
            results_by_type[result_type].append(result)
        
        # 타입별로 출력
        for result_type, type_results in results_by_type.items():
            output += f"## {result_type.capitalize()}\n\n"
            for result in type_results:
                output += f"- **{result.get('name', 'Unnamed')}**\n"
                if result.get('description'):
                    output += f"  - {result.get('description')[:200]}...\n"
                if result.get('id'):
                    output += f"  - ID: {result.get('id')}\n"
            output += "\n"
        
        return output
    except Exception as e:
        print(f"Exception in search_threats: {str(e)}", file=sys.stderr)
        return f"Error searching threats: {str(e)}"

# 프롬프트: 위협 조사
@mcp.prompt()
def investigate_threat(threat_name: str) -> str:
    """특정 위협에 대한 조사 프롬프트"""
    return f"""
I need to investigate the threat actor or malware family known as "{threat_name}". Please:

1. Search for information about this threat
2. Identify any known associated indicators (IPs, domains, file hashes)
3. Summarize their tactics, techniques, and procedures (TTPs)
4. Provide recommendations for defending against this threat

Please use available Mandiant intelligence resources to provide the most accurate information.
"""

# 프롬프트: 취약점 평가
@mcp.prompt()
def assess_vulnerability(cve_id: str) -> str:
    """특정 CVE 취약점 평가 프롬프트"""
    return f"""
I need a comprehensive assessment of the vulnerability {cve_id}. Please:

1. Get detailed information about this vulnerability
2. Explain the potential impact if exploited
3. Identify which systems or software are affected
4. Provide mitigation strategies
5. Determine if this vulnerability is being actively exploited in the wild

Please use Mandiant intelligence to provide an accurate risk assessment.
"""

# 프롬프트: IOC 분석
@mcp.prompt()
def analyze_indicator(indicator_value: str) -> str:
    """특정 표시기(IOC) 분석 프롬프트"""
    return f"""
I need to analyze this potential indicator of compromise: "{indicator_value}". Please:

1. Determine what type of indicator this is (IP, domain, file hash, etc.)
2. Check if it's associated with any known threat actors or malware
3. Find any related intelligence reports
4. Assess the threat level of this indicator
5. Provide recommendations for security teams

Please use Mandiant's indicator analysis to provide detailed information.
"""

if __name__ == "__main__":
    print("Starting MCP server run()...", file=sys.stderr)
    mcp.run()