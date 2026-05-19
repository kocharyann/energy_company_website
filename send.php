<?php
/**
 * Обработчик формы обратной связи с сайта ООО «Энергетическая компания».
 *
 * Принимает POST с полями name, phone, email, comment, consent, website (honeypot).
 * Валидирует данные, отправляет письмо администратору через SMTP (PHPMailer)
 * и редиректит обратно на форму со статусом операции.
 */

declare(strict_types=1);

// ── Подключаем PHPMailer ────────────────────────────────────────────────────
require_once __DIR__ . '/lib/PHPMailer/PHPMailer.php';
require_once __DIR__ . '/lib/PHPMailer/SMTP.php';
require_once __DIR__ . '/lib/PHPMailer/Exception.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// ── Загружаем секреты ───────────────────────────────────────────────────────
$config = require __DIR__ . '/config.php';

// ── Rate-limit: не более 3 заявок с одного IP за 10 минут ──────────────────
/**
 * Проверяет, не превышен ли лимит заявок с текущего IP.
 * Возвращает true, если лимит превышен (надо отказать).
 */
function is_rate_limited(string $logFile, int $maxRequests, int $windowSeconds): bool
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $now = time();
    $cutoff = $now - $windowSeconds;

    // Читаем существующие записи
    $entries = [];
    if (file_exists($logFile)) {
        $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
        foreach ($lines as $line) {
            [$timestamp, $entryIp] = array_pad(explode("\t", $line, 2), 2, '');
            $timestamp = (int)$timestamp;
            // Сохраняем только записи "не старше окна" — старые отбрасываем
            if ($timestamp >= $cutoff) {
                $entries[] = [$timestamp, $entryIp];
            }
        }
    }

    // Считаем, сколько записей с этого IP в окне
    $countFromThisIp = 0;
    foreach ($entries as [$timestamp, $entryIp]) {
        if ($entryIp === $ip) {
            $countFromThisIp++;
        }
    }

    // Если уже исчерпан лимит — отказ
    if ($countFromThisIp >= $maxRequests) {
        return true;
    }

    // Добавляем текущую попытку и перезаписываем файл
    $entries[] = [$now, $ip];
    $newContent = '';
    foreach ($entries as [$timestamp, $entryIp]) {
        $newContent .= $timestamp . "\t" . $entryIp . "\n";
    }
    @file_put_contents($logFile, $newContent, LOCK_EX);

    return false;
}

// Применяем rate-limit (3 попытки за 10 минут)
$rateLimitFile = __DIR__ . '/data/rate-limit.log';
if (is_rate_limited($rateLimitFile, 3, 600)) {
    redirect_back('rate_limit');
}

// ── Логирование заявок: каждая успешная заявка пишется в файл ──────────────
/**
 * Записывает заявку в лог-файл в формате JSON Lines.
 * Каждая строка — отдельная запись, легко парсится позже.
 */
function log_request(string $logFile, array $data): void
{
    $entry = [
        'datetime'  => date('Y-m-d H:i:s'),
        'ip'        => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'name'      => $data['name'] ?? '',
        'phone'     => $data['phone'] ?? '',
        'email'     => $data['email'] ?? '',
        'comment'   => $data['comment'] ?? '',
        'mail_sent' => $data['mail_sent'] ?? false,
    ];

    // JSON_UNESCAPED_UNICODE — чтобы кириллица сохранялась читаемо, а не как \u041f
    $line = json_encode($entry, JSON_UNESCAPED_UNICODE) . "\n";

    // LOCK_EX — чтобы при одновременных заявках записи не перепутались
    @file_put_contents($logFile, $line, FILE_APPEND | LOCK_EX);
}

// ── Утилита: редирект обратно на форму с указанным статусом ─────────────────
function redirect_back(string $status): void

{
    header('Location: index.html?status=' . urlencode($status) . '#request');
    exit;
}

// ── Защита: только POST ────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    redirect_back('error');
}

// ── Honeypot: если бот заполнил скрытое поле "website" — молча отказываем ──
if (!empty($_POST['website'] ?? '')) {
    redirect_back('spam');
}

// ── Считываем и нормализуем поля ────────────────────────────────────────────
$name    = trim((string)($_POST['name']    ?? ''));
$phone   = trim((string)($_POST['phone']   ?? ''));
$email   = trim((string)($_POST['email']   ?? ''));
$comment = trim((string)($_POST['comment'] ?? ''));
$consent = $_POST['consent'] ?? '';

// ── Валидация ───────────────────────────────────────────────────────────────
$errors = [];

if (mb_strlen($name) < 2 || mb_strlen($name) > 100) {
    $errors[] = 'name';
}

// Телефон: должно быть от 10 до 30 символов из цифр, плюса, скобок, дефисов и пробелов
if (!preg_match('/^[0-9+()\-\s]{10,30}$/', $phone)) {
    $errors[] = 'phone';
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL) || mb_strlen($email) > 150) {
    $errors[] = 'email';
}

if (mb_strlen($comment) > 1000) {
    $errors[] = 'comment';
}

// Согласие на обработку ПД должно быть отмечено
if ($consent !== '1') {
    $errors[] = 'consent';
}

if (!empty($errors)) {
    redirect_back('validation');
}

// ── Формируем тело письма ───────────────────────────────────────────────────
$comment_for_mail = $comment !== '' ? $comment : '(не заполнен)';

$html_body = '
    <h2 style="color:#0a2140;margin-bottom:8px;">Новая заявка с сайта</h2>
    <p style="color:#6b7280;font-size:13px;margin-top:0;">
        Получено: ' . htmlspecialchars(date('d.m.Y H:i'), ENT_QUOTES, 'UTF-8') . '
    </p>
    <table cellpadding="6" cellspacing="0" style="border-collapse:collapse;font-size:14px;">
        <tr><td style="font-weight:bold;">Имя:</td>
            <td>' . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . '</td></tr>
        <tr><td style="font-weight:bold;">Телефон:</td>
            <td>' . htmlspecialchars($phone, ENT_QUOTES, 'UTF-8') . '</td></tr>
        <tr><td style="font-weight:bold;">E-mail:</td>
            <td>' . htmlspecialchars($email, ENT_QUOTES, 'UTF-8') . '</td></tr>
        <tr><td style="font-weight:bold;vertical-align:top;">Комментарий:</td>
            <td>' . nl2br(htmlspecialchars($comment_for_mail, ENT_QUOTES, 'UTF-8')) . '</td></tr>
    </table>
    <p style="color:#6b7280;font-size:12px;margin-top:24px;">
        Это автоматическое уведомление с формы обратной связи. Чтобы ответить клиенту,
        просто нажмите «Ответить» — письмо уйдёт на его адрес.
    </p>
';

$plain_body = "Новая заявка с сайта\n"
            . "Получено: " . date('d.m.Y H:i') . "\n\n"
            . "Имя: $name\n"
            . "Телефон: $phone\n"
            . "E-mail: $email\n"
            . "Комментарий: $comment_for_mail\n";

// ── Отправляем письмо через PHPMailer ───────────────────────────────────────
$mail = new PHPMailer(true);

try {
    // Серверные настройки SMTP
    $mail->isSMTP();
    $mail->Host       = $config['smtp_host'];
    $mail->SMTPAuth   = true;
    $mail->Username   = $config['smtp_username'];
    $mail->Password   = $config['smtp_password'];
    $mail->SMTPSecure = $config['smtp_secure'];
    $mail->Port       = $config['smtp_port'];
    $mail->CharSet    = 'UTF-8';

    // Отправитель и получатель
    $mail->setFrom($config['mail_from'], $config['mail_from_name']);
    $mail->addAddress($config['mail_to'], $config['mail_to_name']);

    // Reply-To: при ответе из почты письмо уйдёт клиенту
    $mail->addReplyTo($email, $name);

    // Содержимое письма
    $mail->isHTML(true);
    $mail->Subject = 'Новая заявка с сайта от ' . $name;
    $mail->Body    = $html_body;
    $mail->AltBody = $plain_body;

    $mail->send();

    // Логируем успешную заявку
    log_request(__DIR__ . '/data/requests.log', [
        'name'      => $name,
        'phone'     => $phone,
        'email'     => $email,
        'comment'   => $comment,
        'mail_sent' => true,
    ]);

    redirect_back('success');

} catch (Exception $e) {
    // Логируем заявку, даже если письмо не отправилось — данные не теряем
    log_request(__DIR__ . '/data/requests.log', [
        'name'      => $name,
        'phone'     => $phone,
        'email'     => $email,
        'comment'   => $comment,
        'mail_sent' => false,
    ]);

    // В разработке полезно увидеть конкретную ошибку — раскомментируйте на отладке:
    // echo 'Ошибка отправки: ', $mail->ErrorInfo;
    // exit;
    redirect_back('error');
}


