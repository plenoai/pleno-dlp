# pleno-secret-scanner

Go-native secret scanner. Detector interface is trufflehog-compatible; source connectors are reimplemented in `pkg/sources/`.

## 하네스: secret-scanner

**목표:** trufflehog 호환 Detector + 자체 Source 커넥터로 시크릿을 스캔/검증/리포트하는 Go CLI를 구축·진화시킨다.

**트리거:** 본 리포지토리에서 다음 작업 요청이 들어오면 `secret-scanner-orchestrator` 스킬을 사용한다.
- 새 detector / source 추가, 기존 detector·source 수정
- 엔진/CLI/출력 포맷/CI 변경
- detector·source 인터페이스 변경 (대규모 영향)
- 단순 질문이나 단일 파일 grep 등은 직접 응답.

## 워크플로우 규칙

- 모듈 모두 `go.work`로 묶인 Go workspace. 새 패키지는 `pkg/<area>/<name>/` 아래에 `go.mod` 없이 단일 모듈로 추가한다 (현 시점 단일 모듈 구성).
- 테스트는 `go test ./... -race`. PR 단위로 race detector 통과를 강제한다.
- 배포는 `vX.Y.Z` 태그 push로 GoReleaser가 GitHub Releases 발행 (trusted publishing). main push 즉시 배포는 하지 않는다 (CLI tool이므로).
- secret 노출 위험이 큰 도구이므로, 새 detector는 반드시 `Verify()` 구현 또는 명시적 unverified 표기를 갖는다.

## 변경 이력

| 날짜 | 변경 내용 | 대상 | 사유 |
|------|----------|------|------|
| 2026-05-06 | 초기 하네스 구성 (5 에이전트, 5 스킬) | 전체 | pleno-anonymize 참조하여 신규 구축 |
