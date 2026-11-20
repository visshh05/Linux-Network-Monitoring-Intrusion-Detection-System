"""SQLite storage for captured packets and security alerts."""

from pathlib import Path
import sqlite3
from typing import Any

DATABASE_PATH = Path(__file__).with_name("security.db")


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                protocol TEXT NOT NULL,
                source_port INTEGER,
                destination_port INTEGER,
                packet_size INTEGER NOT NULL,
                timestamp TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );
            """
        )


def insert_packet(packet: dict[str, Any]) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO packets (
                source_ip, destination_ip, protocol, source_port,
                destination_port, packet_size, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                packet["source_ip"], packet["destination_ip"], packet["protocol"],
                packet["source_port"], packet["destination_port"],
                packet["packet_size"], packet["timestamp"],
            ),
        )


def insert_alert(alert: dict[str, Any]) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO alerts (
                source_ip, destination_ip, alert_type, severity,
                description, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                alert["source_ip"], alert["destination_ip"], alert["alert_type"],
                alert["severity"], alert["description"], alert["timestamp"],
            ),
        )


def get_summary() -> dict[str, int]:
    with get_connection() as connection:
        total = connection.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
        alerts = connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        protocol_rows = connection.execute(
            "SELECT protocol, COUNT(*) AS count FROM packets GROUP BY protocol"
        ).fetchall()

    summary = {"total_packets": total, "security_alerts": alerts, "TCP": 0, "UDP": 0, "ICMP": 0}
    summary.update({row["protocol"]: row["count"] for row in protocol_rows})
    return summary


def get_recent_alerts(limit: int = 10) -> list[sqlite3.Row]:
    with get_connection() as connection:
        return connection.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()


def get_recent_packets(limit: int = 20) -> list[sqlite3.Row]:
    with get_connection() as connection:
        return connection.execute(
            "SELECT * FROM packets ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
