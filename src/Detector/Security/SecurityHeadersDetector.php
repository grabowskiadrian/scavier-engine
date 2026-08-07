<?php

namespace Scavier\Detector\Security;

use Scavier\Collector\Data\HttpData;
use Scavier\Collector\HttpCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class SecurityHeadersDetector extends Detector
{
    private const HEADERS = [
        'strict-transport-security' => 'HSTS',
        'content-security-policy' => 'CSP',
        'x-content-type-options' => 'X-Content-Type-Options',
        'x-frame-options' => 'X-Frame-Options',
        'referrer-policy' => 'Referrer-Policy',
        'permissions-policy' => 'Permissions-Policy',
        'x-xss-protection' => 'X-XSS-Protection',
        'cross-origin-opener-policy' => 'COOP',
        'cross-origin-embedder-policy' => 'COEP',
        'cross-origin-resource-policy' => 'CORP',
    ];

    private const GRADES = [
        [0.9, 'A'],
        [0.7, 'B'],
        [0.5, 'C'],
        [0.3, 'D'],
        [0.0, 'F'],
    ];

    public static function dependencies(): array
    {
        return [HttpCollector::class];
    }

    public function detect(Context $context): ?array
    {
        $http = $context->get(HttpData::class);

        if ($http === null) {
            return null;
        }

        $present = [];
        $missing = [];
        $warnings = [];

        foreach (self::HEADERS as $header => $label) {
            $value = $http->header($header);

            if ($value !== null) {
                $entry = ['header' => $label, 'value' => $value];

                $analysis = match ($header) {
                    'strict-transport-security' => $this->analyzeHsts($value),
                    'content-security-policy' => $this->analyzeCsp($value),
                    default => null,
                };

                if ($analysis !== null) {
                    $entry['analysis'] = $analysis;
                    if (!empty($analysis['warnings'])) {
                        $warnings = array_merge($warnings, $analysis['warnings']);
                    }
                }

                $present[] = $entry;
            } else {
                $missing[] = $label;
            }
        }

        $total = count(self::HEADERS);
        $score = count($present) / $total;

        $grade = 'F';
        foreach (self::GRADES as [$threshold, $letter]) {
            if ($score >= $threshold) {
                $grade = $letter;
                break;
            }
        }

        // security.headers — facts (what's present/missing)
        $headers = [
            'present' => $present,
            'missing' => $missing,
        ];

        // audit.security_score — analysis
        $audit = [
            'score' => round($score, 2),
            'grade' => $grade,
            'present_count' => count($present),
            'total_count' => $total,
        ];

        if (!empty($warnings)) {
            $audit['warnings'] = $warnings;
        }

        return [
            'security' => ['headers' => $headers],
            'audit' => ['security_score' => $audit],
        ];
    }

    private function analyzeHsts(string $value): array
    {
        $analysis = [];

        if (preg_match('/max-age=(\d+)/i', $value, $m)) {
            $maxAge = (int) $m[1];
            $analysis['max_age'] = $maxAge;
            $analysis['max_age_days'] = (int) round($maxAge / 86400);
        }

        $analysis['include_subdomains'] = (bool) preg_match('/includeSubDomains/i', $value);
        $analysis['preload'] = (bool) preg_match('/preload/i', $value);

        $analysis['warnings'] = [];
        if (isset($maxAge) && $maxAge < 31536000) {
            $analysis['warnings'][] = 'HSTS max-age is less than 1 year';
        }

        return $analysis;
    }

    private function analyzeCsp(string $value): array
    {
        $analysis = [];
        $analysis['warnings'] = [];

        $hasUnsafeInline = (bool) preg_match("/['\"]?unsafe-inline['\"]?/i", $value);
        $hasUnsafeEval = (bool) preg_match("/['\"]?unsafe-eval['\"]?/i", $value);
        $hasWildcard = (bool) preg_match('/\s\*(\s|;|$)/', $value);

        $analysis['unsafe_inline'] = $hasUnsafeInline;
        $analysis['unsafe_eval'] = $hasUnsafeEval;
        $analysis['wildcard_source'] = $hasWildcard;

        if ($hasUnsafeInline) {
            $analysis['warnings'][] = "CSP allows 'unsafe-inline' — XSS risk";
        }
        if ($hasUnsafeEval) {
            $analysis['warnings'][] = "CSP allows 'unsafe-eval' — code injection risk";
        }
        if ($hasWildcard) {
            $analysis['warnings'][] = 'CSP uses wildcard (*) source — overly permissive';
        }

        return $analysis;
    }
}
