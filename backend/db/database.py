import json
import logging
import os
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from psycopg2.pool import SimpleConnectionPool

logger = logging.getLogger(__name__)

SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def _with_sslmode(database_url: str) -> str:
    parts = urlsplit(database_url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.setdefault("sslmode", "require")
    return urlunsplit(parts._replace(query=urlencode(query)))


def create_pool() -> SimpleConnectionPool | None:
    database_url = os.environ.get("DATABASE_URL", "").strip()
    if not database_url:
        logger.warning("DATABASE_URL is not configured; persistence is disabled")
        return None

    # Neon -pooler endpoints are preferred for serverless workloads when supplied.
    # The app uses DATABASE_URL exactly as configured rather than rewriting hosts.
    try:
        return SimpleConnectionPool(
            1,
            5,
            dsn=_with_sslmode(database_url),
        )
    except Exception as exc:
        logger.warning("Could not initialize database connection pool: %s", exc)
        return None


def initialize_schema(pool: SimpleConnectionPool | None) -> None:
    if pool is None:
        return

    connection = None
    try:
        connection = pool.getconn()
        with connection.cursor() as cursor:
            cursor.execute(SCHEMA_PATH.read_text(encoding="utf-8"))
        connection.commit()
    except Exception as exc:
        if connection is not None:
            try:
                connection.rollback()
            except Exception as rollback_exc:
                logger.warning("Could not roll back schema initialization: %s", rollback_exc)
        logger.warning("Could not initialize database schema: %s", exc)
    finally:
        if connection is not None:
            _release_connection(pool, connection)


def close_pool(pool: SimpleConnectionPool | None) -> None:
    if pool is not None:
        try:
            pool.closeall()
        except Exception as exc:
            logger.warning("Could not close database connection pool: %s", exc)


def _release_connection(pool: SimpleConnectionPool, connection: Any) -> None:
    try:
        pool.putconn(connection)
    except Exception as exc:
        logger.warning("Could not release database connection: %s", exc)


def get_cached_result(pool: SimpleConnectionPool | None, email_hash: str) -> dict[str, Any] | None:
    if pool is None:
        return None

    connection = None
    try:
        connection = pool.getconn()
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT result_json FROM analyses WHERE email_hash = %s",
                (email_hash,),
            )
            row = cursor.fetchone()
        return dict(row[0]) if row else None
    except Exception as exc:
        logger.warning("Could not read cached analysis: %s", exc)
        return None
    finally:
        if connection is not None:
            _release_connection(pool, connection)


def store_analysis(
    pool: SimpleConnectionPool | None,
    *,
    email_hash: str,
    filename: str | None,
    result: dict[str, Any],
) -> None:
    if pool is None:
        return

    llm_analysis = result.get("llm_analysis") or {}
    phishing_analysis = result.get("phishing_analysis") or {}
    result_json = json.dumps(result, default=str)
    connection = None
    try:
        connection = pool.getconn()
        with connection.cursor() as cursor:
            verdict = (
                llm_analysis.get("final_recommended_risk_level")
                or phishing_analysis.get("verdict")
            )
            cursor.execute(
                """
                INSERT INTO analyses (
                    email_hash, filename, result_json, risk_level, verdict,
                    llm_verdict, ml_agreement
                )
                VALUES (%s, %s, %s::jsonb, %s, %s, %s, %s)
                ON CONFLICT (email_hash) DO NOTHING
                """,
                (
                    email_hash,
                    filename,
                    result_json,
                    result.get("primary_verdict"),
                    verdict,
                    llm_analysis.get("llm_verdict"),
                    llm_analysis.get("ml_agreement"),
                ),
            )
        connection.commit()
    except Exception as exc:
        if connection is not None:
            try:
                connection.rollback()
            except Exception as rollback_exc:
                logger.warning("Could not roll back analysis insert: %s", rollback_exc)
        logger.warning("Could not store analysis: %s", exc)
    finally:
        if connection is not None:
            _release_connection(pool, connection)


def list_cases(pool: SimpleConnectionPool | None, limit: int) -> list[dict[str, Any]]:
    if pool is None:
        return []

    connection = None
    try:
        connection = pool.getconn()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, filename, uploaded_at, risk_level, verdict,
                       llm_verdict, ml_agreement
                FROM analyses
                ORDER BY uploaded_at DESC
                LIMIT %s
                """,
                (limit,),
            )
            columns = [description[0] for description in cursor.description]
            rows = cursor.fetchall()
        return [dict(zip(columns, row)) for row in rows]
    except Exception as exc:
        logger.warning("Could not list analysis history: %s", exc)
        return []
    finally:
        if connection is not None:
            _release_connection(pool, connection)


def get_case(pool: SimpleConnectionPool | None, case_id: int) -> dict[str, Any] | None:
    if pool is None:
        return None

    connection = None
    try:
        connection = pool.getconn()
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT result_json FROM analyses WHERE id = %s",
                (case_id,),
            )
            row = cursor.fetchone()
        return dict(row[0]) if row else None
    except Exception as exc:
        logger.warning("Could not retrieve analysis %s: %s", case_id, exc)
        return None
    finally:
        if connection is not None:
            _release_connection(pool, connection)
