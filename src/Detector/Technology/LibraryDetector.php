<?php

namespace Scavier\Detector\Technology;

use Scavier\Collector\Data\HtmlData;
use Scavier\Collector\HtmlCollector;
use Scavier\Engine\Context;
use Scavier\Engine\Contract\Detector;

class LibraryDetector extends Detector
{
    private const PATTERNS = [
        'jQuery' => '/jquery[.\-\/].*\.js/i',
        'Bootstrap' => '/bootstrap[.\-\/].*\.(js|css)/i',
        'Font Awesome' => '/fontawesome|font-awesome/i',
        'Lodash' => '/lodash(\.min)?\.js/i',
        'Moment.js' => '/moment(\.min)?\.js/i',
        'Axios' => '/axios(\.min)?\.js/i',
        'HTMX' => '/htmx(\.min)?\.js/i',
        'Turbo' => '/turbo(\.min)?\.js/i',
        'Livewire' => '/livewire\.js/i',
        'Tailwind CSS' => '/tailwindcss|tailwind(\.min)?\.css/i',
        'Swiper' => '/swiper[.\-\/].*\.js/i',
        'GSAP' => '/gsap(\.min)?\.js/i',
        'D3.js' => '/d3(\.min)?\.js|d3[.\-\/].*\.js/i',
        'Chart.js' => '/chart(\.min)?\.js|chart\.js[.\-\/]/i',
        'Three.js' => '/three(\.min)?\.js/i',
        'Leaflet' => '/leaflet[.\-\/].*\.(js|css)/i',
        'Mapbox' => '/mapbox-gl[.\-\/].*\.(js|css)/i',
        'Socket.io' => '/socket\.io(\.min)?\.js/i',
        'Lottie' => '/lottie[.\-\/].*\.js/i',
        'AOS' => '/aos[.\-\/].*\.(js|css)/i',
        'Anime.js' => '/anime(\.min)?\.js/i',
        'Highlight.js' => '/highlight(\.min)?\.(js|css)/i',
        'Prism.js' => '/prism(\.min)?\.(js|css)/i',
        'Slick' => '/slick[.\-\/].*\.(js|css)/i',
        'Owl Carousel' => '/owl\.carousel/i',
    ];

    private const VERSION_PATTERN = '/[\/@]([\d]+(?:\.[\d]+){1,3})/';

    public static function dependencies(): array
    {
        return [
            HtmlCollector::class,
        ];
    }

    public function detect(Context $context): ?array
    {
        $html = $context->get(HtmlData::class);

        if ($html === null) {
            return null;
        }

        $results = [];

        $allSources = array_merge($html->scripts, $html->stylesheets);

        foreach (self::PATTERNS as $name => $pattern) {
            $matches = array_values(array_filter($allSources, fn(string $src) => preg_match($pattern, $src)));

            if (!empty($matches)) {
                $entry = [
                    'value' => $name,
                    'confidence' => 0.9,
                    'evidence' => 'Script/style src: ' . $matches[0],
                ];

                // Extract version from URL
                if (preg_match(self::VERSION_PATTERN, $matches[0], $vm)) {
                    $entry['version'] = $vm[1];
                }

                $results[] = $entry;
            }
        }

        if (empty($results)) {
            return null;
        }

        $tags = array_column($results, 'value');

        return [
            'technology' => [
                'libraries' => $results,
            ],
            '_tags' => $tags,
        ];
    }
}
