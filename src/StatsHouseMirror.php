<?php
// Copyright 2022 V Kontakte LLC
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

declare(strict_types = 1);

namespace VK\StatsHouse;

use InvalidArgumentException;
use Prometheus\Collector;
use Prometheus\CollectorRegistry;
use Prometheus\RenderTextFormat;
use Prometheus\Storage\InMemory;
use Throwable;

/**
 * StatsHouse stays primary. This wrapper mirrors counters and values into
 * Prometheus and POSTs the text exposition. Mirror and push failures stay here.
 * Unique metrics are not mirrored.
 */
class StatsHouseMirror {
  private const NAMESPACE = 'sh_mirror';
  private const VALUE_BUCKETS = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000,
  ];

  private StatsHouse $sh;
  private CollectorRegistry $registry;
  private bool $enabled;
  /** @var array<string, string> */
  private array $constLabels = [];
  /** @var array<string, true> */
  private array $exclude = [];
  /** @var callable|null */
  private $sender = null;
  private string $pushUrl = '';
  private float $timeoutSec = 5.0;
  private float $pushIntervalSec = 15.0;
  private float $lastPushTs = 0.0;
  private string $transport = 'stream';
  private bool $dirty = false;
  /** @var array<string, string> sanitized prom name => original metric */
  private array $sources = [];
  /** @var array<string, string> sanitized prom name => counter|histogram */
  private array $kinds = [];
  /** @var array<string, string[]> sanitized prom name => label names */
  private array $labelSets = [];

  /**
   * @param array<string, mixed> $options
   */
  public function __construct(StatsHouse $sh, array $options = []) {
    $this->sh = $sh;
    $this->registry = new CollectorRegistry(new InMemory(), false);
    $this->enabled = (bool)($options['enabled'] ?? true);
    $this->transport = function_exists('curl_init') ? 'curl' : 'stream';
    $this->lastPushTs = microtime(true);

    foreach (['product_id', 'service', 'instance'] as $name) {
      if (isset($options[$name]) && is_string($options[$name])) {
        $this->constLabels[$name] = $options[$name];
      }
    }
    if (isset($options['exclude']) && is_array($options['exclude'])) {
      foreach ($options['exclude'] as $name) {
        if (is_string($name) && $name !== '') {
          $this->exclude[$name] = true;
        }
      }
    }
    if (isset($options['sender'])) {
      if (!is_callable($options['sender'])) {
        throw new InvalidArgumentException('sender must be callable');
      }
      $this->sender = $options['sender'];
    }
    if (isset($options['push_url'])) {
      if (!is_string($options['push_url'])) {
        throw new InvalidArgumentException('push_url must be an http or https URL');
      }
      self::validatePushUrl($options['push_url']);
      $this->pushUrl = $options['push_url'];
    }
    if (isset($options['timeout_sec']) && is_numeric($options['timeout_sec'])) {
      $timeout = (float)$options['timeout_sec'];
      if ($timeout > 0) {
        $this->timeoutSec = $timeout;
      }
    }
    if (isset($options['push_interval_sec']) && is_numeric($options['push_interval_sec'])) {
      $interval = (float)$options['push_interval_sec'];
      $this->pushIntervalSec = $interval > 0 ? $interval : 0.0;
    }
    if ($options['push_on_shutdown'] ?? true) {
      register_shutdown_function(function (): void {
        $this->push();
      });
    }
  }

  /**
   * @param string[] $keys
   */
  public function writeCount(string $metric, $keys, float $count, int $ts): ?string {
    $err = $this->sh->writeCount($metric, $keys, $count, $ts);
    try {
      $this->mirrorCount($metric, $keys, $count);
      $this->maybePush();
    } catch (Throwable $e) {
    }
    return $err;
  }

  /**
   * @param string[] $keys
   * @param float[] $values
   */
  public function writeValue(string $metric, $keys, $values, float $count, int $ts): ?string {
    $err = $this->sh->writeValue($metric, $keys, $values, $count, $ts);
    try {
      $this->mirrorValue($metric, $keys, $values);
      $this->maybePush();
    } catch (Throwable $e) {
    }
    return $err;
  }

  /**
   * @param string[] $keys
   * @param int[] $values
   */
  public function writeUnique(string $metric, $keys, $values, float $count, int $ts): ?string {
    return $this->sh->writeUnique($metric, $keys, $values, $count, $ts);
  }

  public function render(): string {
    if (!$this->enabled) {
      return '';
    }
    $metrics = $this->registry->getMetricFamilySamples();
    if ($metrics === []) {
      return '';
    }
    return (new RenderTextFormat())->render($metrics);
  }

  public function push(): void {
    try {
      $this->lastPushTs = microtime(true);
      if (!$this->dirty) {
        return;
      }
      $body = $this->render();
      if ($body === '') {
        $this->dirty = false;
        return;
      }
      if ($this->sender !== null) {
        ($this->sender)($body);
      } elseif ($this->pushUrl !== '' && !$this->httpPost($body)) {
        return;
      }
      $this->dirty = false;
    } catch (Throwable $e) {
    }
  }

  /**
   * @param string[] $keys
   */
  private function mirrorCount(string $metric, $keys, float $count): void {
    if (!$this->shouldMirror($metric) || !is_finite($count) || $count <= 0) {
      return;
    }
    $name = $this->sanitizeMetric($metric);
    $labels = $this->labelMap($keys);
    if ($name === null || $labels === null || !$this->lockSeries($name, $metric, 'counter', $labels)) {
      return;
    }
    $this->registry
      ->getOrRegisterCounter(self::NAMESPACE, $name, 'StatsHouse counter mirrored to Prometheus', array_keys($labels))
      ->incBy($count, array_values($labels));
    $this->dirty = true;
  }

  /**
   * @param string[] $keys
   * @param float[] $values
   */
  private function mirrorValue(string $metric, $keys, $values): void {
    if (!$this->shouldMirror($metric) || !is_array($values)) {
      return;
    }
    $finite = [];
    foreach ($values as $value) {
      if (!is_int($value) && !is_float($value)) {
        continue;
      }
      $value = (float)$value;
      if (is_finite($value)) {
        $finite[] = $value;
      }
    }
    if ($finite === []) {
      return;
    }
    $name = $this->sanitizeMetric($metric);
    $labels = $this->labelMap($keys);
    if ($name === null || $labels === null || !$this->lockSeries($name, $metric, 'histogram', $labels)) {
      return;
    }
    $histogram = $this->registry->getOrRegisterHistogram(
      self::NAMESPACE,
      $name,
      'StatsHouse value mirrored as histogram',
      array_keys($labels),
      self::VALUE_BUCKETS
    );
    foreach ($finite as $value) {
      $histogram->observe($value, array_values($labels));
    }
    $this->dirty = true;
  }

  private function shouldMirror(string $metric): bool {
    return $this->enabled && $metric !== '' && !isset($this->exclude[$metric]);
  }

  /**
   * First metric name, kind, and label set win. Later conflicts are dropped.
   *
   * @param array<string, string> $labels
   */
  private function lockSeries(string $name, string $metric, string $kind, array $labels): bool {
    if (isset($this->sources[$name]) && $this->sources[$name] !== $metric) {
      return false;
    }
    if (isset($this->kinds[$name]) && $this->kinds[$name] !== $kind) {
      return false;
    }
    $names = array_keys($labels);
    if (isset($this->labelSets[$name]) && $this->labelSets[$name] !== $names) {
      return false;
    }
    $this->sources[$name] = $metric;
    $this->kinds[$name] = $kind;
    $this->labelSets[$name] = $names;
    return true;
  }

  private function maybePush(): void {
    if ($this->pushIntervalSec <= 0) {
      return;
    }
    if ((microtime(true) - $this->lastPushTs) < $this->pushIntervalSec) {
      return;
    }
    $this->push();
  }

  private function sanitizeMetric(string $metric): ?string {
    $name = preg_replace('/[^a-zA-Z0-9_:]/', '_', $metric);
    if (!is_string($name) || $name === '') {
      return null;
    }
    try {
      Collector::assertValidMetricName(self::NAMESPACE . '_' . $name);
    } catch (InvalidArgumentException $e) {
      return null;
    }
    return $name;
  }

  /**
   * @param int|string $key
   */
  private function tagName($key): string {
    if (is_int($key)) {
      return (string)($key + 1);
    }
    $name = (string)$key;
    if (strlen($name) >= 2 && $name[0] === '_' && is_numeric($name[1])) {
      return substr($name, 1);
    }
    return $name;
  }

  private function sanitizeLabel(string $name): ?string {
    if ($name === '') {
      return null;
    }
    if (preg_match('/^[0-9]+$/', $name) === 1) {
      $name = 'tag_' . $name;
    }
    $name = preg_replace('/[^a-zA-Z0-9_]/', '_', $name);
    if (!is_string($name) || $name === '') {
      return null;
    }
    if (preg_match('/^[a-zA-Z_]/', $name) !== 1) {
      $name = '_' . $name;
    }
    if (strpos($name, '__') === 0) {
      $name = 'l' . $name;
    }
    if ($name === 'le') {
      $name = 'le_label';
    }
    try {
      Collector::assertValidLabel($name);
    } catch (InvalidArgumentException $e) {
      return null;
    }
    return $name;
  }

  /**
   * @param mixed $keys
   * @return array<string, string>|null
   */
  private function labelMap($keys): ?array {
    if (!is_array($keys)) {
      return null;
    }
    $labels = [];
    foreach ($keys as $key => $value) {
      if (!is_scalar($value)) {
        return null;
      }
      $name = $this->sanitizeLabel($this->tagName($key));
      if ($name === null || array_key_exists($name, $labels)) {
        return null;
      }
      $labels[$name] = (string)$value;
    }
    foreach ($this->constLabels as $name => $value) {
      $labels[$name] = $value;
    }
    ksort($labels, SORT_STRING);
    return $labels;
  }

  private static function validatePushUrl(string $url): void {
    if ($url === '' || preg_match('/[\x00-\x20\x7f]/', $url) === 1 || preg_match('/%0(?:0|a|d)/i', $url) === 1) {
      throw new InvalidArgumentException('push_url must be an http or https URL');
    }
    $parts = parse_url($url);
    $scheme = strtolower((string)(is_array($parts) ? ($parts['scheme'] ?? '') : ''));
    $host = is_array($parts) ? (string)($parts['host'] ?? '') : '';
    if (($scheme !== 'http' && $scheme !== 'https') || $host === '') {
      throw new InvalidArgumentException('push_url must be an http or https URL');
    }
  }

  private function httpPost(string $body): bool {
    try {
      if ($this->transport === 'curl') {
        return $this->postCurl($body);
      }
      return $this->postStream($body);
    } catch (Throwable $e) {
      return false;
    }
  }

  private function postCurl(string $body): bool {
    if (!function_exists('curl_init') || $this->pushUrl === '') {
      return false;
    }
    $ch = curl_init($this->pushUrl);
    if ($ch === false) {
      return false;
    }
    $timeoutMs = (int)max(1, round($this->timeoutSec * 1000));
    $options = [
      CURLOPT_POST => true,
      CURLOPT_POSTFIELDS => $body,
      CURLOPT_HTTPHEADER => ['Content-Type: ' . RenderTextFormat::MIME_TYPE],
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_FOLLOWLOCATION => false,
      CURLOPT_TIMEOUT_MS => $timeoutMs,
      CURLOPT_CONNECTTIMEOUT_MS => $timeoutMs,
    ];
    if (defined('CURLOPT_PROTOCOLS_STR')) {
      $options[CURLOPT_PROTOCOLS_STR] = 'http,https';
    } elseif (defined('CURLOPT_PROTOCOLS') && defined('CURLPROTO_HTTP') && defined('CURLPROTO_HTTPS')) {
      $options[CURLOPT_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS;
    }
    if (defined('CURLOPT_REDIR_PROTOCOLS_STR')) {
      $options[CURLOPT_REDIR_PROTOCOLS_STR] = 'http,https';
    } elseif (defined('CURLOPT_REDIR_PROTOCOLS') && defined('CURLPROTO_HTTP') && defined('CURLPROTO_HTTPS')) {
      $options[CURLOPT_REDIR_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS;
    }
    curl_setopt_array($ch, $options);
    $result = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    return $result !== false && $code >= 200 && $code < 300;
  }

  private function postStream(string $body): bool {
    if ($this->pushUrl === '') {
      return false;
    }
    $context = stream_context_create([
      'http' => [
        'method' => 'POST',
        'header' => 'Content-Type: ' . RenderTextFormat::MIME_TYPE . "\r\n",
        'content' => $body,
        'timeout' => $this->timeoutSec,
        'ignore_errors' => true,
        'follow_location' => 0,
        'max_redirects' => 0,
      ],
    ]);
    $http_response_header = null;
    $result = @file_get_contents($this->pushUrl, false, $context);
    if ($result === false || !isset($http_response_header[0]) || !is_string($http_response_header[0])) {
      return false;
    }
    if (preg_match('/\s(\d{3})\s/', $http_response_header[0], $matches) !== 1) {
      return false;
    }
    $code = (int)$matches[1];
    return $code >= 200 && $code < 300;
  }
}
