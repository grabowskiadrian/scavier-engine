<?php

namespace Scavier\Tests\Detector;

use PHPUnit\Framework\TestCase;
use Scavier\Collector\Data\DnsData;
use Scavier\Detector\Infrastructure\MailSenderDetector;
use Scavier\Engine\Context;

final class MailSenderDetectorTest extends TestCase
{
    private function contextWithSpf(string $spf): Context
    {
        $context = new Context();
        $context->set(new DnsData(domain: 'example.com', txt: [['txt' => $spf]]));
        return $context;
    }

    public function testDetectsMailerLite(): void
    {
        $result = (new MailSenderDetector())->detect(
            $this->contextWithSpf('v=spf1 include:_spf.mlsend.com ~all')
        );

        $this->assertSame('MailerLite', $result['infrastructure']['mail_senders'][0]['value']);
        $this->assertSame(0.85, $result['infrastructure']['mail_senders'][0]['confidence']);
    }

    public function testDetectsMultipleSenders(): void
    {
        $result = (new MailSenderDetector())->detect(
            $this->contextWithSpf('v=spf1 include:_spf.google.com include:sendgrid.net include:_spf.mlsend.com ~all')
        );

        $values = array_column($result['infrastructure']['mail_senders'], 'value');
        $this->assertContains('MailerLite', $values);
        $this->assertContains('SendGrid', $values);
        $this->assertContains('Google Workspace', $values);
    }

    public function testDetectsMailchimp(): void
    {
        $result = (new MailSenderDetector())->detect(
            $this->contextWithSpf('v=spf1 include:servers.mcsv.net include:spf.mandrillapp.com ~all')
        );

        $values = array_column($result['infrastructure']['mail_senders'], 'value');
        $this->assertContains('Mailchimp', $values);
    }

    public function testDetectsAmazonSes(): void
    {
        $result = (new MailSenderDetector())->detect(
            $this->contextWithSpf('v=spf1 include:amazonses.com -all')
        );

        $this->assertSame('Amazon SES', $result['infrastructure']['mail_senders'][0]['value']);
    }

    public function testReturnsNullWithoutSpf(): void
    {
        $context = new Context();
        $context->set(new DnsData(domain: 'example.com', txt: [['txt' => 'google-site-verification=abc']]));

        $this->assertNull((new MailSenderDetector())->detect($context));
    }

    public function testReturnsNullWhenNoKnownSenders(): void
    {
        $result = (new MailSenderDetector())->detect(
            $this->contextWithSpf('v=spf1 ip4:1.2.3.4 -all')
        );

        $this->assertNull($result);
    }
}
