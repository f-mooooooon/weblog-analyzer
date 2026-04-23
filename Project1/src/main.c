#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"
#include "parser.h"
#include "analyzer.h"
#include "detector.h"
#include "report.h"

static void print_usage(const char* prog)
{
    printf("Usage: %s <logfile> [top_n] [s]\n\n", prog);
    printf("  <logfile>  path to log file (required)\n");
    printf("  [top_n]    show top N IPs/URLs (default: 10)\n");
    printf("  [s]        show suspicious requests only\n");
}

int main(int argc, char* argv[])
{
    int top_n = 10;
    int suspicious_only = 0;

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (argc >= 3) {
        if (strcmp(argv[2], "s") == 0)
            suspicious_only = 1;
        else {
            top_n = atoi(argv[2]);
            if (top_n <= 0) top_n = 10;
        }
    }

    const char* filepath = argv[1];

    FILE* fp = fopen(filepath, "r");
    if (!fp) {
        fprintf(stderr, "Error: cannot open file: %s\n", filepath);
        return 1;
    }

    /* 스택 대신 힙에 할당 (구조체가 너무 커서 스택 오버플로우 방지) */
    AnalysisContext* ctx = (AnalysisContext*)malloc(sizeof(AnalysisContext));
    if (!ctx) {
        fprintf(stderr, "Error: memory allocation failed\n");
        fclose(fp);
        return 1;
    }

    printf("\nAnalyzing: %s\n\n", filepath);
    init_context(ctx);

    char line[MAX_LINE_LEN];
    while (fgets(line, sizeof(line), fp)) {
        ctx->total_lines++;
        line[strcspn(line, "\n")] = '\0';
        if (line[0] == '\0') continue;

        LogEntry entry;
        if (parse_log_line(line, &entry) != 0) {
            ctx->parse_errors++;
            continue;
        }

        analyze_entry(ctx, &entry);

        if (is_suspicious(&entry)) {
            if (ctx->suspicious_count < MAX_SUSPICIOUS)
                ctx->suspicious[ctx->suspicious_count++] = entry;
        }
    }

    fclose(fp);
    finalize_analysis(ctx);

    if (suspicious_only) {
        report_suspicious(ctx);
    }
    else {
        report_summary(ctx);
        report_top_ips(ctx, top_n);
        report_top_urls(ctx, top_n);
        report_status(ctx);
        report_hourly(ctx);
        report_suspicious(ctx);
    }

    free_context(ctx);
    free(ctx);
    return 0;
}