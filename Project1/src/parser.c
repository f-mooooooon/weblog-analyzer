#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "parser.h"

/*
* Windows에는 strptime이 없으므로 직접 구현  
* 입력 예: "22/Mar/2026:09:00:01 +0900"
*/
static time_t parse_timestamp(const char* ts_str)
{
    int day, year, hour, min, sec;
    char month_str[8] = { 0 };

    /* 날짜/시간 파싱 */
    if (sscanf(ts_str, "%d/%3s/%d:%d:%d:%d",
        &day, month_str, &year, &hour, &min, &sec) != 6) {
        return (time_t)-1;
    }

    /* 월 이름 → 숫자 변환 */
    const char* months[] = {
        "Jan","Feb","Mar","Apr","May","Jun",
        "Jul","Aug","Sep","Oct","Nov","Dec"
    };
    int month = -1;
    int i;
    for (i = 0; i < 12; i++) {
        if (strcmp(month_str, months[i]) == 0) {
            month = i;
            break;
        }
    }
    if (month == -1) return (time_t)-1;

    /* tm 구조체 채우기 */
    struct tm t = { 0 };
    t.tm_year = year - 1900;  /* 1900년 기준 */
    t.tm_mon = month;        /* 0~11 */
    t.tm_mday = day;
    t.tm_hour = hour;
    t.tm_min = min;
    t.tm_sec = sec;
    t.tm_isdst = -1;

    return mktime(&t);
}

/* parse_log_line() */
int parse_log_line(const char* line, LogEntry* entry)
{
    char ts_str[64] = { 0 };
    char request[2048] = { 0 };

    int matched = sscanf(line,
        "%45s %*s %63s [%63[^]]] \"%2047[^\"]\" %d %ld \"%1023[^\"]\" \"%255[^\"]\"",
        entry->ip,
        entry->user,
        ts_str,
        request,
        &entry->status,
        &entry->bytes,
        entry->referer,
        entry->user_agent
    );

    if (matched < 6) return -1;

    entry->timestamp = parse_timestamp(ts_str);

    sscanf(request, "%7s %1023s %15s",
        entry->method, entry->url, entry->protocol);

    return 0;
}