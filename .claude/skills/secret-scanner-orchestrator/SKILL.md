---
name: secret-scanner-orchestrator
description: pleno-secret-scanner 의 5인 에이전트 팀(architect, detector-engineer, connector-engineer, core-engineer, qa)을 조율하여 detector·source·engine·CLI 작업을 한 번에 진행한다. 새 detector·source 추가, 인터페이스 변경, 엔진/CLI/출력 포맷 변경, 릴리스 파이프라인 작업, 또는 "다시 실행", "재실행", "보완", "이전 결과 기반으로 개선", "<영역>만 다시" 등 후속 요청에서 본 스킬을 사용한다. 단순 한줄 grep 이나 사실 확인은 직접 응답하고 본 스킬을 트리거하지 않는다.
---

# secret-scanner-orchestrator

## 목적

pleno-secret-scanner 의 모든 의미있는 변경(detector/source 추가, 인터페이스 수정, 엔진/CLI 변경, 릴리스 작업)을 5인 에이전트 팀의 협업으로 수행한다. trufflehog 호환 detector 인터페이스와 자체 source 커넥터의 정합성을 유지하면서 점진 진화시킨다.

## 실행 모드

**에이전트 팀 (기본).** 5명 모두를 `TeamCreate`로 팀에 묶고, `TaskCreate`로 작업을 할당한다. 팀원은 `SendMessage`로 직접 통신한다.

예외: 단일 detector 1개만 추가하는 경량 요청은 **서브 에이전트 모드**로 detector-engineer 만 호출. 인터페이스 영향이 없으므로 팀 오버헤드를 줄인다.

## Phase 0: 컨텍스트 확인

워크플로우 시작 시:

1. 리포지토리 루트에 `_workspace/` 가 존재하는지 확인.
   - **존재 + 사용자가 부분 수정 요청** → 부분 재실행 모드. 해당 영역 owner 에이전트만 호출.
   - **존재 + 사용자가 새 입력 제공** → `_workspace/` 를 `_workspace_prev/` 로 백업하고 새 실행.
   - **미존재** → 초기 실행 (`_workspace/` 생성).
2. `git status` 가 dirty 하면 `gh wt` 로 워크트리 분기 후 진행.

## Phase 1: 작업 분류

요청을 다음 분류 중 하나로 매핑:

| 분류 | 주 owner | 협업자 |
|---|---|---|
| 새 detector 1~N개 추가 | detector-engineer | qa (e2e 검증) |
| 새 source 1~N개 추가 | connector-engineer | core-engineer (등록), qa |
| 인터페이스 변경 (Detector / Source / Result / Chunk) | architect → detector-engineer + connector-engineer | core-engineer, qa |
| CLI / 엔진 / 출력 변경 | core-engineer | qa |
| 릴리스 / CI / 의존성 | architect | (필요 시 모두에게 SendMessage 알림) |
| 회귀 수정 | qa 보고 → 해당 owner | architect (인프라 원인일 때) |

## Phase 2: 팀 구성 + 작업 할당

1. `TeamCreate(team_name="secret-scanner", members=["architect", "detector-engineer", "connector-engineer", "core-engineer", "qa"])`.
2. 분류 결과에 맞춰 `TaskCreate` 작업 분해. 의존성은 `addBlockedBy` 로 명시.
3. 각 task 의 owner 를 명시 지정.

기본 의존 패턴:
- 인터페이스 변경 → architect 가 시그니처 결정 → detector-engineer / connector-engineer 동시 갱신 → core-engineer 가 engine 적응 → qa 검증.
- 새 detector → detector-engineer 구현 → core-engineer 등록 확인 → qa e2e.

## Phase 3: 모니터링 + 종합

- 팀원이 `TaskUpdate` 로 진행 상황 갱신. 30분 진척 없으면 SendMessage 로 점검.
- 완료된 결과를 `_workspace/<phase>_<owner>_<artifact>.md` 에 누적.
- qa 의 회귀 보고가 들어오면 즉시 해당 owner 에게 재할당.

## Phase 4: 마무리

1. qa 가 최종 e2e + race 통과 확인 후 `_workspace/qa-report-<date>.md` 발행.
2. `_workspace/` 의 의사결정·변경 노트를 종합하여 한 줄 PR title + 본문 초안 생성.
3. CLAUDE.md 변경 이력 테이블 갱신 (어떤 에이전트가 어떤 변화를 주도했는가 기록).
4. `TeamDelete` 로 팀 정리.

## 데이터 전달 프로토콜

| 종류 | 방식 |
|---|---|
| 작업 조율 | `TaskCreate` / `TaskUpdate` |
| 실시간 통신 | `SendMessage` (1~2 문장, 결정사항만) |
| 산출물 | `_workspace/<phase>_<owner>_<artifact>.md` (인간 가독), 코드는 `pkg/...` |
| 인터페이스 의사결정 | `_workspace/architecture-decisions.md` (ADR 누적) |

## 에러 핸들링

- 한 에이전트가 실패: 1회 재시도. 재실패 시 결과 없이 진행하고 회귀 노트 남김.
- 인터페이스 충돌 (detector-engineer 와 connector-engineer 가 다른 시그니처 가정): 즉시 architect 가 결정권자. 양쪽 모두 architect 의 결정에 맞춰 재작업.
- qa 가 동일 회귀를 2회 보고: 임시 해결 금지, 근본 원인 ADR 작성 후 수정.

## 팀 크기 적정성

5명 (대규모 기준 적정). 인터페이스 변경 시 모두 동시 작동, 단순 detector 추가 시 detector-engineer + qa 만으로 축약 가능.

## 테스트 시나리오

**정상:** "Slack Bot Token detector 추가" → 작업 분해: detector-engineer (구현) → core-engineer (registry 확인) → qa (e2e fixture). 30분 내 PR 초안.

**에러:** detector-engineer 가 새 시그니처를 임의 도입 → connector-engineer task 가 컴파일 실패 보고 → orchestrator 가 architect 호출 → ADR 작성 후 양쪽 재작업 → qa 검증 → 정상 종료.
