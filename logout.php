<?php
// FAILLE : session_start() sans options de securite (OWASP A07:2021 - Authentication Failures)
// Sans les options ci-dessous, le cookie de session est vulnerable jusqu'a sa destruction.
// Ancien code vulnerable : session_start();
require_once __DIR__ . '/init.php';
secure_session_start();
session_destroy();
header('Location: login.php');
exit;
