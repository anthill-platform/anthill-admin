
from anthill.common.model import Model
from anthill.common.database import DatabaseError
from anthill.common.validate import validate

import ujson


class AuditLogError(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message


class AuditLogActionAdapter(object):
    def __init__(self, data):
        self.action_id = str(data.get("action_id"))
        self.service_name = data.get("service_name")
        self.service_action = data.get("service_action")
        self.icon = data.get("action_icon")
        self.message = data.get("action_message")
        self.payload = data.get("action_payload")
        self.date = data.get("action_date")
        self.author = str(data.get("action_author"))


class AuditLogModel(Model):
    def __init__(self, db):
        self.db = db

    def get_setup_tables(self):
        return ["audit_log"]

    def get_setup_db(self):
        return self.db

    @validate(gamespace_id="int", service_name="str_name", service_action="str_name",
              action_icon="str", action_message="str", action_payload="json_dict", action_author="int")
    async def audit_log(self, gamespace_id, service_name, service_action, action_icon,
                        action_message, action_payload, action_author):
        try:
            await self.db.execute(
                """
                INSERT INTO `audit_log`
                (`gamespace_id`, `service_name`, `service_action`, 
                 `action_icon`, `action_message`, `action_payload`, `action_author`) 
                VALUES (%s, %s, %s, %s, %s, %s, %s);
                """, gamespace_id, service_name, service_action, action_icon,
                action_message, ujson.dumps(action_payload), action_author
            )
        except DatabaseError as e:
            raise AuditLogError(500, e.args[1])

    async def list_log(self, gamespace_id, offset=0, limit=100):
        try:
            entries = await self.db.query(
                """
                SELECT SQL_CALC_FOUND_ROWS * 
                FROM `audit_log`
                WHERE `gamespace_id`=%s
                ORDER BY `action_date` DESC
                LIMIT %s, %s;
                """, gamespace_id, offset, limit)

        except DatabaseError as e:
            raise AuditLogError(500, e.args[1])
        else:
            return list(map(AuditLogActionAdapter, entries))

    async def list_paged_count(self, gamespace_id, offset=0, limit=100):
        try:
            async with self.db.acquire() as db:
                entries = await db.query(
                    """
                    SELECT SQL_CALC_FOUND_ROWS * 
                    FROM `audit_log`
                    WHERE `gamespace_id`=%s
                    ORDER BY `action_date` DESC
                    LIMIT %s, %s;
                    """, gamespace_id, offset, limit)

                count_result = await db.get(
                    """
                        SELECT FOUND_ROWS() AS count;
                    """)
                total_rows = count_result["count"]

        except DatabaseError as e:
            raise AuditLogError(500, e.args[1])
        else:
            return list(map(AuditLogActionAdapter, entries)), total_rows
