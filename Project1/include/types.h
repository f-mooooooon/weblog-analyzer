#ifndef TYPES_H
#define TYPES_H

#include <time.h>

/* 상수 정의 */
#define HASH_SIZE       1024   /* 해시맵 버킷 수 */
#define MAX_SUSPICIOUS  10000  /* 의심 요청 최대 저장 수 */
#define MAX_LINE_LEN    4096   /* 로그 한 줄 최대 길이 */

/* 파싱된 로그 한 줄을 담는 구조체 */
typedef struct {
    char    ip[46];           /* 클라이언트 IP (IPv4/IPv6) */
    char    user[64];         /* 인증 사용자 ('-' 이면 비로그인) */
    time_t  timestamp;        /* 요청 시각 (epoch 정수) */
    char    method[8];        /* HTTP 메서드: GET, POST 등 */
    char    url[1024];        /* 요청 URL 경로 */
    char    protocol[16];     /* HTTP/1.1 등 */
    int     status;           /* HTTP 상태코드: 200, 404 등 */
    long    bytes;            /* 응답 바이트 수 */
    char    referer[1024];    /* 이전 페이지 URL */
    char    user_agent[256];  /* 브라우저/클라이언트 정보 */
} LogEntry;

/* IP별 요청 수 (해시맵 연결 리스트 노드) */
typedef struct IpStat {
    char            ip[46];
    int             count;
    struct IpStat  *next;     /* 해시 충돌 시 다음 노드 */
} IpStat;

/* URL별 접근 수 (해시맵 연결 리스트 노드) */
typedef struct UrlStat {
    char            url[1024];
    int             count;
    struct UrlStat *next;
} UrlStat;

/* 시간대별(0~23시) 트래픽 */
typedef struct {
    int  requests[24];  /* 시간대별 요청 수 */
    long bytes[24];     /* 시간대별 전송 바이트 */
} HourlyTraffic;

/* HTTP 상태코드 통계 */
typedef struct {
    int s1xx;           /* 1xx 합계 */
    int s2xx;           /* 2xx 합계 */
    int s3xx;           /* 3xx 합계 */
    int s4xx;           /* 4xx 합계 */
    int s5xx;           /* 5xx 합계 */
    int detail[600];    /* detail[200] = 200 응답 수, detail[404] = 404 수 */
} StatusStat;

/* 분석 결과 전체를 담는 컨텍스트(모든 모듈이 이 구조체를 공유) */
typedef struct {
    IpStat        *ip_table[HASH_SIZE];   /* IP 해시맵 */
    UrlStat       *url_table[HASH_SIZE];  /* URL 해시맵 */
    HourlyTraffic  hourly;                /* 시간대별 통계 */
    StatusStat     status;                /* 상태코드 통계 */

    int  total_lines;                     /* 전체 줄 수 */
    int  parse_errors;                    /* 파싱 실패 줄 수 */

    LogEntry  suspicious[MAX_SUSPICIOUS]; /* 의심 요청 목록 */
    int       suspicious_count;           /* 의심 요청 수 */
} AnalysisContext;

#endif /* TYPES_H */
