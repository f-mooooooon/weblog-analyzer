#ifndef DETECTOR_H
#define DETECTOR_H

#include "types.h"

/*
 * is_suspicious()
 * ───────────────
 * entry가 의심 요청이면 1, 아니면 0 반환
 * 탐지 패턴: SQL Injection, Path Traversal,
 *            악성 스캐너 봇, 비정상 메서드
 */
int is_suspicious(const LogEntry *entry);

/*
 * get_suspicious_reason()
 * ───────────────────────
 * 의심 이유 문자열을 buf에 채워 반환
 * (is_suspicious()가 1을 반환한 경우에만 의미 있음)
 */
void get_suspicious_reason(const LogEntry *entry, char *buf, int buf_size);

#endif /* DETECTOR_H */
