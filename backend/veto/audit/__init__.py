"""Audit log backends. `open_audit(target)` picks one: a postgresql:// URL, otherwise a SQLite path or ':memory:'."""

from veto.audit.chain import AuditLog


def open_audit(target: str):
    if target.startswith(("postgresql://", "postgres://")):
        from veto.audit.postgres import PostgresAuditLog  # imported lazily: psycopg is optional for SQLite users
        return PostgresAuditLog(target)
    return AuditLog(target)


__all__ = ["AuditLog", "open_audit"]
