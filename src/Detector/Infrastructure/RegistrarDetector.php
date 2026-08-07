<?php

namespace Scavier\Detector\Infrastructure;

use Scavier\Collector\Data\DomainWhoisData;
use Scavier\Collector\Data\RdapData;
use Scavier\Collector\DomainWhoisCollector;
use Scavier\Collector\RdapCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class RegistrarDetector extends Detector
{
    public static function dependencies(): array
    {
        return [RdapCollector::class, DomainWhoisCollector::class];
    }

    public function detect(Context $context): ?array
    {
        $rdap = $context->get(RdapData::class);
        $whois = $context->get(DomainWhoisData::class);

        if ($rdap === null && $whois === null) {
            return null;
        }

        $domain = $rdap->domain ?? $whois->domain ?? '';

        $result = [
            'domain' => $domain,
            'confidence' => 1.0,
            'evidence' => $this->buildEvidence($rdap, $whois),
        ];

        // Registrar: prefer RDAP, fallback to WHOIS
        $registrar = $rdap?->registrar ?? $whois?->registrar;
        if ($registrar !== null) {
            $result['registrar'] = $registrar;
        }

        // Registration date
        $regDate = $rdap?->registrationDate ?? $whois?->creationDate;
        if ($regDate !== null) {
            $result['registered'] = $regDate;

            $regTime = strtotime($regDate);
            if ($regTime !== false) {
                $ageYears = round((time() - $regTime) / (365.25 * 86400), 1);
                $result['domain_age_years'] = $ageYears;
                $result['domain_age_category'] = match (true) {
                    $ageYears < 1 => 'new',
                    $ageYears < 5 => 'established',
                    default => 'mature',
                };
            }
        }

        // Expiration date
        $expDate = $rdap?->expirationDate ?? $whois?->expirationDate;
        if ($expDate !== null) {
            $result['expires'] = $expDate;

            $daysUntilExpiry = (int) round((strtotime($expDate) - time()) / 86400);
            if ($daysUntilExpiry <= 30 && $daysUntilExpiry > 0) {
                $result['expiring_soon'] = true;
            }
        }

        // Updated date
        $updDate = $rdap?->lastUpdated ?? $whois?->updatedDate;
        if ($updDate !== null) {
            $result['updated'] = $updDate;
        }

        // Status (RDAP only)
        if ($rdap !== null && !empty($rdap->status)) {
            $result['status'] = $rdap->status;
        }

        // Registrant info (WHOIS enrichment)
        if ($whois !== null) {
            if ($whois->registrant !== null) {
                $result['registrant'] = $whois->registrant;
            }
            if ($whois->registrantOrganization !== null) {
                $result['registrant_organization'] = $whois->registrantOrganization;
            }
            if ($whois->registrantCountry !== null) {
                $result['registrant_country'] = $whois->registrantCountry;
            }
            if ($whois->registrantEmail !== null) {
                $result['registrant_email'] = $whois->registrantEmail;
            }
            if ($whois->dnssecStatus !== null) {
                $result['dnssec'] = $whois->dnssecStatus;
            }
        }

        $tags = [];
        if ($registrar !== null) {
            $tags[] = $registrar;
        }

        return ['domain' => ['registration' => $result], '_tags' => $tags];
    }

    private function buildEvidence(?RdapData $rdap, ?DomainWhoisData $whois): string
    {
        $sources = [];
        if ($rdap !== null) {
            $sources[] = 'RDAP';
        }
        if ($whois !== null) {
            $sources[] = 'WHOIS';
        }

        return implode(' + ', $sources) . ' query';
    }
}
