#ifndef PARSER_H
#define PARSER_H

#include "types.h"

/*
 * parse_log_line()
 * ────────────────
 * Apache Combined Log 형식의 문자열 한 줄을 파싱해서
 * entry 구조체에 결과를 채워 넣는다.
 *
 * 반환값:  0  → 성공
 *         -1  → 파싱 실패 (형식이 맞지 않는 줄)
 */
int parse_log_line(const char *line, LogEntry *entry);

#endif /* PARSER_H */
