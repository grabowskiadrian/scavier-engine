<?php

namespace Scavier\Detector\Technology;

use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\HtmlCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class StructuredDataDetector extends Detector
{
    public static function dependencies(): array
    {
        return [HtmlCollector::class];
    }

    public function detect(Context $context): ?array
    {
        $html = $context->get(HtmlData::class);

        if ($html === null || empty($html->jsonLd)) {
            return null;
        }

        $types = [];

        foreach ($html->jsonLd as $item) {
            $type = $item['@type'] ?? null;

            if ($type !== null) {
                if (is_array($type)) {
                    $types = array_merge($types, $type);
                } else {
                    $types[] = $type;
                }
            }

            // Handle @graph
            if (isset($item['@graph']) && is_array($item['@graph'])) {
                foreach ($item['@graph'] as $graphItem) {
                    $graphType = $graphItem['@type'] ?? null;
                    if ($graphType !== null) {
                        if (is_array($graphType)) {
                            $types = array_merge($types, $graphType);
                        } else {
                            $types[] = $graphType;
                        }
                    }
                }
            }
        }

        $types = array_values(array_unique($types));

        if (empty($types)) {
            return null;
        }

        return [
            'technology' => [
                'structured_data' => [
                    'format' => 'JSON-LD',
                    'types' => $types,
                    'count' => count($html->jsonLd),
                    'confidence' => 1.0,
                    'evidence' => 'application/ld+json script tags',
                ],
            ]
        ];
    }
}
