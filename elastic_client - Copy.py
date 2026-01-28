from elasticsearch import Elasticsearch, ConnectionError
from .log_parser import extract_platform_from_log, extract_timestamp_from_log

ES_HOST = "http://localhost:9200"
INDEX_NAME = "soc-logs"

es = Elasticsearch(ES_HOST)

def fetch_latest_logs(size=100):
    try:
        response = es.search(
            index=INDEX_NAME,
            size=size,
            sort=[{"@timestamp": {"order": "desc"}}],
            query={"match_all": {}}
        )
    except ConnectionError:
        return []

    logs = []
    for hit in response["hits"]["hits"]:
        src = hit["_source"]
        log_text = src.get("log", "")
        logs.append({
            "log": log_text,
            "platform": src.get("platform") or extract_platform_from_log(log_text),
            "timestamp": src.get("@timestamp") or extract_timestamp_from_log(log_text),
            "severity": src.get("severity", "Unknown"),
            "severity_number": src.get("severity_number", 0)
        })
    return logs
