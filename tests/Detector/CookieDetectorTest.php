<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\HttpData;
use Scavier\Detector\Security\CookieDetector;
use Scavier\Engine\Context;

final class CookieDetectorTest extends TestCase
{
    public function testDetectsCookies(): void
    {
        $context = new Context();
        $context->set(new HttpData(
            statusCode: 200,
            headers: ['set-cookie' => ['session=abc; Path=/; Secure; HttpOnly']],
            body: '',
            cookies: ['session' => 'abc'],
        ));

        $result = (new CookieDetector())->detect($context);

        $this->assertSame(1, $result['security']['cookies']['count']);
        $this->assertSame('session', $result['security']['cookies']['cookies'][0]['name']);
        $this->assertContains('secure', $result['security']['cookies']['attributes']['session']);
        $this->assertContains('httponly', $result['security']['cookies']['attributes']['session']);
    }

    public function testIdentifiesTrackers(): void
    {
        $context = new Context();
        $context->set(new HttpData(
            statusCode: 200,
            headers: [],
            body: '',
            cookies: ['_ga' => 'GA1.2.123', '_fbp' => 'fb.1.123'],
        ));

        $result = (new CookieDetector())->detect($context);

        $this->assertContains('Google Analytics', $result['security']['cookies']['trackers']);
        $this->assertContains('Facebook Pixel', $result['security']['cookies']['trackers']);
    }

    public function testReturnsNullWhenNoCookies(): void
    {
        $context = new Context();
        $context->set(new HttpData(statusCode: 200, headers: [], body: ''));

        $this->assertNull((new CookieDetector())->detect($context));
    }
}
