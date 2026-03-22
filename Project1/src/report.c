#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "report.h"
#include "detector.h"

#define MAX_NODES 65536

static void print_separator(void)
{
    printf("==================================================\n");
}

static void print_header(const char* title)
{
    print_separator();
    printf("  %s\n", title);
    print_separator();
}

void report_summary(const AnalysisContext* ctx)
{
    print_header("[ SUMMARY ]");
    int valid = ctx->total_lines - ctx->parse_errors;
    double error_rate = ctx->total_lines > 0
        ? (double)ctx->parse_errors / ctx->total_lines * 100.0 : 0.0;
    printf("  Total lines     : %d\n", ctx->total_lines);
    printf("  Valid requests  : %d\n", valid);
    printf("  Parse errors    : %d (%.1f%%)\n", ctx->parse_errors, error_rate);
    printf("  Suspicious      : %d\n", ctx->suspicious_count);
    printf("\n");
}

static int compare_ip_stat(const void* a, const void* b)
{
    return (*(IpStat**)b)->count - (*(IpStat**)a)->count;
}

void report_top_ips(const AnalysisContext* ctx, int top_n)
{
    print_header("[ TOP IPs ]");

    /* 힙에 배열 할당 */
    IpStat** arr = (IpStat**)malloc(MAX_NODES * sizeof(IpStat*));
    if (!arr) { printf("  Memory error\n\n"); return; }

    int total = 0, i;
    for (i = 0; i < HASH_SIZE; i++) {
        IpStat* node = ctx->ip_table[i];
        while (node && total < MAX_NODES) {
            arr[total++] = node;
            node = node->next;
        }
    }

    qsort(arr, total, sizeof(IpStat*), compare_ip_stat);

    int limit = (top_n < total) ? top_n : total;
    printf("  %-20s  %s\n", "IP Address", "Requests");
    printf("  %-20s  %s\n", "--------------------", "--------");
    for (i = 0; i < limit; i++)
        printf("  %-20s  %d\n", arr[i]->ip, arr[i]->count);
    printf("\n");

    free(arr);
}

static int compare_url_stat(const void* a, const void* b)
{
    return (*(UrlStat**)b)->count - (*(UrlStat**)a)->count;
}

void report_top_urls(const AnalysisContext* ctx, int top_n)
{
    print_header("[ TOP URLs ]");

    UrlStat** arr = (UrlStat**)malloc(MAX_NODES * sizeof(UrlStat*));
    if (!arr) { printf("  Memory error\n\n"); return; }

    int total = 0, i;
    for (i = 0; i < HASH_SIZE; i++) {
        UrlStat* node = ctx->url_table[i];
        while (node && total < MAX_NODES) {
            arr[total++] = node;
            node = node->next;
        }
    }

    qsort(arr, total, sizeof(UrlStat*), compare_url_stat);

    int limit = (top_n < total) ? top_n : total;
    printf("  %-50s  %s\n", "URL", "Requests");
    printf("  %-50s  %s\n", "--------------------------------------------------", "--------");
    for (i = 0; i < limit; i++)
        printf("  %-50.49s  %d\n", arr[i]->url, arr[i]->count);
    printf("\n");

    free(arr);
}

void report_status(const AnalysisContext* ctx)
{
    print_header("[ HTTP STATUS CODES ]");
    printf("  1xx (Info)      : %d\n", ctx->status.s1xx);
    printf("  2xx (Success)   : %d\n", ctx->status.s2xx);
    printf("  3xx (Redirect)  : %d\n", ctx->status.s3xx);
    printf("  4xx (Client Err): %d\n", ctx->status.s4xx);
    printf("  5xx (Server Err): %d\n", ctx->status.s5xx);
    printf("\n");
    int common[] = { 200,201,204,301,302,304,400,401,403,404,405,500,502,503,0 };
    int i;
    printf("  %-8s  %s\n", "Code", "Count");
    printf("  %-8s  %s\n", "--------", "--------");
    for (i = 0; common[i] != 0; i++)
        if (ctx->status.detail[common[i]] > 0)
            printf("  %-8d  %d\n", common[i], ctx->status.detail[common[i]]);
    printf("\n");
}

void report_hourly(const AnalysisContext* ctx)
{
    print_header("[ HOURLY TRAFFIC ]");
    int max_req = 1, h, b;
    for (h = 0; h < 24; h++)
        if (ctx->hourly.requests[h] > max_req) max_req = ctx->hourly.requests[h];
    for (h = 0; h < 24; h++) {
        int req = ctx->hourly.requests[h];
        int bar_len = (int)((double)req / max_req * 30);
        printf("  %02d:00 |", h);
        for (b = 0; b < bar_len; b++)  printf("#");
        for (b = bar_len; b < 30; b++) printf(".");
        printf("  %d\n", req);
    }
    printf("\n");
}

void report_suspicious(const AnalysisContext* ctx)
{
    print_header("[ SUSPICIOUS REQUESTS ]");
    if (ctx->suspicious_count == 0) {
        printf("  No suspicious requests detected.\n\n");
        return;
    }
    int i;
    for (i = 0; i < ctx->suspicious_count; i++) {
        const LogEntry* e = &ctx->suspicious[i];
        char ts_buf[32] = "-";
        if (e->timestamp != (time_t)-1) {
            struct tm* t = localtime(&e->timestamp);
            if (t) strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S", t);
        }
        char reason[256];
        get_suspicious_reason(e, reason, sizeof(reason));
        printf("  [%d] %s  %s %s  ->  %s\n",
            i + 1, ts_buf, e->ip, e->url, reason);
    }
    printf("\n");
}