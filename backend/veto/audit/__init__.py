"""Audit log backends. `open_audit(target, tenant)` picks one: a postgresql:// URL, otherwise a SQLite path or
':memory:'. The returned log is bound to that tenant for its whole life (invariant 8)."""

from veto.audit.chain import DEFAULT_TENANT, AuditLog


def open_audit(target: str, tenant: str = DEFAULT_TENANT):
    if target.startswith(("postgresql://", "postgres://")):
        from veto.audit.postgres import PostgresAuditLog  # imported lazily: psycopg is optional for SQLite users
        return PostgresAuditLog(target, tenant)
    return AuditLog(target, tenant)


__all__ = ["DEFAULT_TENANT", "AuditLog", "open_audit"]
