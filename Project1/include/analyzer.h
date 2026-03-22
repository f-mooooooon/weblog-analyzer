#ifndef ANALYZER_H
#define ANALYZER_H

#include "types.h"

/* 컨텍스트 초기화 (프로그램 시작 시 1회 호출) */
void init_context(AnalysisContext *ctx);

/* LogEntry 하나를 받아 통계 누적 */
void analyze_entry(AnalysisContext *ctx, const LogEntry *entry);

/* 분석 완료 후 정렬 등 후처리 (출력 직전 1회 호출) */
void finalize_analysis(AnalysisContext *ctx);

/* 메모리 해제 (프로그램 종료 시 호출) */
void free_context(AnalysisContext *ctx);

#endif /* ANALYZER_H */
