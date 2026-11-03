from sqlite3 import Connection

from app.db.connection import get_connection


ROLES = {
    "administrator": "Full SENTINEL AI platform administration.",
    "security_analyst": "Perform authorized AI security assessments.",
    "auditor": "Read-only assessment and evidence review.",
}


PERMISSIONS = {
    "users.read": "View user accounts.",
    "users.manage": "Create, update and deactivate users.",
    "roles.read": "View role definitions.",
    "roles.manage": "Manage role assignments and permissions.",
    "targets.read": "View approved AI test targets.",
    "targets.manage": "Manage AI target configurations.",
    "models.read": "View model configurations.",
    "models.manage": "Manage model configurations.",
    "test_cases.read": "View approved security test cases.",
    "test_cases.manage": "Manage security test cases.",
    "assessments.create": "Create security assessments.",
    "assessments.read": "View assessments.",
    "assessments.execute": "Execute approved assessment tests.",
    "findings.read": "View security findings.",
    "evidence.metadata.read": "View evidence metadata.",
    "security_events.read": "View security monitoring events.",
    "audit_log.read": "View audit history.",
}


ADMIN_PERMISSIONS = tuple(PERMISSIONS.keys())

ANALYST_PERMISSIONS = (
    "targets.read",
    "models.read",
    "test_cases.read",
    "assessments.create",
    "assessments.read",
    "assessments.execute",
    "findings.read",
    "evidence.metadata.read",
    "security_events.read",
)

AUDITOR_PERMISSIONS = (
    "assessments.read",
    "findings.read",
    "evidence.metadata.read",
    "audit_log.read",
)

ROLE_PERMISSION_MAP = {
    "administrator": ADMIN_PERMISSIONS,
    "security_analyst": ANALYST_PERMISSIONS,
    "auditor": AUDITOR_PERMISSIONS,
}


def seed_rbac(connection: Connection) -> dict[str, int]:
    """Insert initial roles and permissions without creating duplicates."""

    for role_name, description in ROLES.items():
        connection.execute(
            """
            INSERT OR IGNORE INTO roles (id, name, description)
            VALUES (?, ?, ?)
            """,
            (f"role-{role_name}", role_name, description),
        )

    for permission_name, description in PERMISSIONS.items():
        permission_id = "perm-" + permission_name.replace(".", "-")

        connection.execute(
            """
            INSERT OR IGNORE INTO permissions (id, name, description)
            VALUES (?, ?, ?)
            """,
            (permission_id, permission_name, description),
        )

    # Resolve actual database IDs rather than assuming existing IDs.
    role_ids = {
        name: record_id
        for record_id, name in connection.execute(
            "SELECT id, name FROM roles"
        )
    }

    permission_ids = {
        name: record_id
        for record_id, name in connection.execute(
            "SELECT id, name FROM permissions"
        )
    }

    for role_name, permission_names in ROLE_PERMISSION_MAP.items():
        for permission_name in permission_names:
            connection.execute(
                """
                INSERT OR IGNORE INTO role_permissions
                    (role_id, permission_id)
                VALUES (?, ?)
                """,
                (
                    role_ids[role_name],
                    permission_ids[permission_name],
                ),
            )

    return {
        "roles": connection.execute(
            "SELECT COUNT(*) FROM roles"
        ).fetchone()[0],
        "permissions": connection.execute(
            "SELECT COUNT(*) FROM permissions"
        ).fetchone()[0],
        "role_assignments": connection.execute(
            "SELECT COUNT(*) FROM role_permissions"
        ).fetchone()[0],
    }


def main() -> None:
    with get_connection() as connection:
        result = seed_rbac(connection)

    print("RBAC seeding successful.")
    for name, count in result.items():
        print(f"{name}: {count}")


if __name__ == "__main__":
    main()