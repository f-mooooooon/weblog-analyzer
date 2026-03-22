#define _CRT_SECURE_NO_WARNINGS
#include <string.h>
#include <stdio.h>
#include "detector.h"

static const char* SQL_PATTERNS[] = {
    "' OR ", "' or ",
    "1=1",   "OR 1=1",
    "UNION SELECT", "union select",
    "DROP TABLE",   "drop table",
    "--", ";--", "xp_",
    NULL
};

static const char* TRAVERSAL_PATTERNS[] = {
    "../", "..\\",
    "%2e%2e%2f",
    "%252e%252e",
    NULL
};

static const char* BAD_AGENTS[] = {
    "sqlmap", "nikto", "nmap",
    "masscan", "zgrab", "dirbuster",
    "nuclei", "acunetix", "burpsuite",
    NULL
};

static const char* BAD_METHODS[] = {
    "TRACE", "TRACK", "DEBUG",
    NULL
};

static int contains_pattern(const char* haystack, const char* const* patterns)
{
    int i;
    for (i = 0; patterns[i] != NULL; i++)
        if (strstr(haystack, patterns[i]) != NULL) return 1;
    return 0;
}

int is_suspicious(const LogEntry* entry)
{
    if (contains_pattern(entry->url, SQL_PATTERNS))      return 1;
    if (contains_pattern(entry->url, TRAVERSAL_PATTERNS)) return 1;
    if (contains_pattern(entry->user_agent, BAD_AGENTS))        return 1;
    if (contains_pattern(entry->method, BAD_METHODS))       return 1;
    if (strlen(entry->url) > 512)                               return 1;
    return 0;
}

void get_suspicious_reason(const LogEntry* entry, char* buf, int buf_size)
{
    if (contains_pattern(entry->url, SQL_PATTERNS))
        snprintf(buf, buf_size, "SQL Injection detected");
    else if (contains_pattern(entry->url, TRAVERSAL_PATTERNS))
        snprintf(buf, buf_size, "Path Traversal detected");
    else if (contains_pattern(entry->user_agent, BAD_AGENTS))
        snprintf(buf, buf_size, "Malicious scanner (UA: %.80s)", entry->user_agent);
    else if (contains_pattern(entry->method, BAD_METHODS))
        snprintf(buf, buf_size, "Abnormal HTTP method: %s", entry->method);
    else if (strlen(entry->url) > 512)
        snprintf(buf, buf_size, "Abnormally long URL (%zu bytes)", strlen(entry->url));
    else
        snprintf(buf, buf_size, "Unknown");
}