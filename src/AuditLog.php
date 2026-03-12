<?php

class AuditLog
{
    public static function log(Config $config, string $action, ?string $userId = null, array $details = []): void
    {
        $st = $config->db()->prepare(
            "INSERT INTO audit_log (user_id, action, ip_address, user_agent, details, created_at)
             VALUES (:uid, :action, :ip, :ua, :details, :created_at)"
        );
        $st->execute([
            ':uid'        => $userId,
            ':action'     => $action,
            ':ip'         => $_SERVER['REMOTE_ADDR'] ?? null,
            ':ua'         => $_SERVER['HTTP_USER_AGENT'] ?? null,
            ':details'    => !empty($details) ? json_encode($details) : null,
            ':created_at' => time(),
        ]);
    }

    public static function query(Config $config, array $filters = [], int $limit = 100, int $offset = 0): array
    {
        $where = [];
        $params = [];

        if (!empty($filters['user_id'])) {
            $where[] = "a.user_id = :uid";
            $params[':uid'] = $filters['user_id'];
        }
        if (!empty($filters['action'])) {
            $where[] = "a.action = :action";
            $params[':action'] = $filters['action'];
        }
        if (!empty($filters['date_from'])) {
            $where[] = "a.created_at >= :date_from";
            $params[':date_from'] = (int)$filters['date_from'];
        }
        if (!empty($filters['date_to'])) {
            $where[] = "a.created_at <= :date_to";
            $params[':date_to'] = (int)$filters['date_to'];
        }

        $whereClause = !empty($where) ? 'WHERE ' . implode(' AND ', $where) : '';

        // Count total
        $countSql = "SELECT COUNT(*) FROM audit_log a {$whereClause}";
        $st = $config->db()->prepare($countSql);
        $st->execute($params);
        $total = (int) $st->fetchColumn();

        // Fetch rows
        $sql = "SELECT a.*, u.username
                FROM audit_log a
                LEFT JOIN users u ON a.user_id = u.id
                {$whereClause}
                ORDER BY a.created_at DESC
                LIMIT :lim OFFSET :off";
        $st = $config->db()->prepare($sql);
        foreach ($params as $k => $v) {
            $st->bindValue($k, $v);
        }
        $st->bindValue(':lim', $limit, PDO::PARAM_INT);
        $st->bindValue(':off', $offset, PDO::PARAM_INT);
        $st->execute();

        return ['entries' => $st->fetchAll(), 'total' => $total];
    }
}
