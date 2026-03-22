#ifndef REPORT_H
#define REPORT_H

#include "types.h"

/* 전체 요약 (총 요청 수, 에러율 등) */
void report_summary(const AnalysisContext *ctx);

/* 요청 수 상위 N개 IP */
void report_top_ips(const AnalysisContext *ctx, int top_n);

/* 접근 빈도 상위 N개 URL */
void report_top_urls(const AnalysisContext *ctx, int top_n);

/* HTTP 상태코드 분포 */
void report_status(const AnalysisContext *ctx);

/* 시간대별 트래픽 (ASCII 바 차트) */
void report_hourly(const AnalysisContext *ctx);

/* 의심 요청 목록 */
void report_suspicious(const AnalysisContext *ctx);

#endif /* REPORT_H */
