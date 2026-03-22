#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "analyzer.h"

/* ───────────────────────────────────────────
   해시 함수: 문자열 → 버킷 인덱스
   (djb2 알고리즘 - 간단하고 분포가 좋음)
─────────────────────────────────────────── */
static unsigned int hash_str(const char *str)
{
    unsigned int hash = 5381;
    int c;
    while ((c = (unsigned char)*str++)) {
        hash = hash * 33 + c;
    }
    return hash % HASH_SIZE;
}

/* ───────────────────────────────────────────
   init_context()
   AnalysisContext를 전부 0으로 초기화
─────────────────────────────────────────── */
void init_context(AnalysisContext *ctx)
{
    memset(ctx, 0, sizeof(AnalysisContext));
}

/* ───────────────────────────────────────────
   내부 헬퍼: IP 해시맵에 카운트 +1
─────────────────────────────────────────── */
static void count_ip(AnalysisContext *ctx, const char *ip)
{
    unsigned int idx = hash_str(ip);
    IpStat *node = ctx->ip_table[idx];

    /* 이미 같은 IP가 있으면 카운트만 올림 */
    while (node) {
        if (strcmp(node->ip, ip) == 0) {
            node->count++;
            return;
        }
        node = node->next;
    }

    /* 없으면 새 노드 생성 후 리스트 앞에 연결 */
    IpStat *new_node = (IpStat *)malloc(sizeof(IpStat));
    if (!new_node) return;  /* malloc 실패 시 그냥 무시 */

    strncpy(new_node->ip, ip, sizeof(new_node->ip) - 1);
    new_node->count = 1;
    new_node->next  = ctx->ip_table[idx];  /* 기존 리스트 앞에 삽입 */
    ctx->ip_table[idx] = new_node;
}

/* ───────────────────────────────────────────
   내부 헬퍼: URL 해시맵에 카운트 +1
─────────────────────────────────────────── */
static void count_url(AnalysisContext *ctx, const char *url)
{
    unsigned int idx = hash_str(url);
    UrlStat *node = ctx->url_table[idx];

    while (node) {
        if (strcmp(node->url, url) == 0) {
            node->count++;
            return;
        }
        node = node->next;
    }

    UrlStat *new_node = (UrlStat *)malloc(sizeof(UrlStat));
    if (!new_node) return;

    strncpy(new_node->url, url, sizeof(new_node->url) - 1);
    new_node->count = 1;
    new_node->next  = ctx->url_table[idx];
    ctx->url_table[idx] = new_node;
}

/* ───────────────────────────────────────────
   내부 헬퍼: 상태코드 카운트 누적
─────────────────────────────────────────── */
static void count_status(AnalysisContext *ctx, int status)
{
    /* 범위 체크: 100~599만 유효 */
    if (status >= 100 && status < 600) {
        ctx->status.detail[status]++;
    }

    /* 계열별 합계 */
    if      (status < 200) ctx->status.s1xx++;
    else if (status < 300) ctx->status.s2xx++;
    else if (status < 400) ctx->status.s3xx++;
    else if (status < 500) ctx->status.s4xx++;
    else                   ctx->status.s5xx++;
}

/* ───────────────────────────────────────────
   analyze_entry()
   LogEntry 하나를 받아 모든 통계에 반영
─────────────────────────────────────────── */
void analyze_entry(AnalysisContext *ctx, const LogEntry *entry)
{
    /* IP 통계 */
    count_ip(ctx, entry->ip);

    /* URL 통계 */
    count_url(ctx, entry->url);

    /* 상태코드 통계 */
    count_status(ctx, entry->status);

    /* 시간대별 통계 */
    if (entry->timestamp != (time_t)-1) {
        struct tm *t = localtime(&entry->timestamp);
        if (t) {
            int hour = t->tm_hour;  /* 0 ~ 23 */
            ctx->hourly.requests[hour]++;
            ctx->hourly.bytes[hour] += entry->bytes;
        }
    }
}

/* ───────────────────────────────────────────
   finalize_analysis()
   현재는 후처리 없음 — 필요 시 정렬 등 추가
─────────────────────────────────────────── */
void finalize_analysis(AnalysisContext *ctx)
{
    (void)ctx;  /* 미사용 경고 방지 */
}

/* ───────────────────────────────────────────
   free_context()
   malloc으로 만든 해시맵 노드들 전부 해제
─────────────────────────────────────────── */
void free_context(AnalysisContext *ctx)
{
    /* IP 해시맵 해제 */
    for (int i = 0; i < HASH_SIZE; i++) {
        IpStat *node = ctx->ip_table[i];
        while (node) {
            IpStat *tmp = node->next;
            free(node);
            node = tmp;
        }
    }

    /* URL 해시맵 해제 */
    for (int i = 0; i < HASH_SIZE; i++) {
        UrlStat *node = ctx->url_table[i];
        while (node) {
            UrlStat *tmp = node->next;
            free(node);
            node = tmp;
        }
    }
}
