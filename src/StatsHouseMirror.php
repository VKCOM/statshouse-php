<?php
// Copyright 2022 V Kontakte LLC
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

declare(strict_types = 1);

namespace VK\StatsHouse;

use InvalidArgumentException;
use Throwable;

#ifndef KPHP
if (!function_exists(__NAMESPACE__ . '\\warning')) {
  function warning(string $message): void {
    error_log($message);
  }
}
#endif

/**
 * KPHP-compilable. StatsHouse stays primary.
 * Counters and values are mirrored into Prometheus text and POSTed.
 * Each successful push sends only the delta since the previous successful
 * push, then clears that delta. A failed push keeps it for the retry.
 * Unique metrics are not mirrored.
 */
class StatsHouseMirror {
  private const NAMESPACE = 'sh_mirror';
  private const TEXT_MIME = 'text/plain; version=0.0.4';
  private const VALUE_BUCKETS = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000,
  ];

  private StatsHouse $sh;
  /** @var array<string, string[]> */
  private array $counterSeries = [];
  /** @var array<string, float> */
  private array $counterValue = [];
  /** @var array<string, string[]> */
  private array $counterLabels = [];
  /** @var array<string, string[]> */
  private array $histogramSeries = [];
  /** @var array<string, float> */
  private array $histogramSum = [];
  /** @var array<string, float> */
  private array $histogramCount = [];
  /** @var array<string, float> */
  private array $histogramBucket = [];
  /** @var array<string, string[]> */
  private array $histogramLabels = [];
  /** @var array<string, array<string, string>> */
  private array $seriesLabels = [];
  private bool $enabled = true;
  /** @var array<string, string> */
  private array $constLabels = [];
  /** @var array<string, true> */
  private array $exclude = [];
  /** @var array<string, true> */
  private array $include = [];
  private string $pushUrl = '';
  private float $timeoutSec = 1.0;
  private float $pushIntervalSec = 15.0;
  private float $lastPushTs = 0.0;
  private string $transport = 'curl';
  private bool $dirty = false;

  /**
   * @param array $options
   */
  public function __construct(StatsHouse $sh, array $options = []) {
    $this->sh = $sh;
    $enabled = $options['enabled'] ?? true;
    $this->enabled = is_bool($enabled) ? $enabled : (bool)$enabled;
    $this->transport = function_exists('curl_init') ? 'curl' : 'stream';
    $this->lastPushTs = microtime(true);

    foreach (['product_id', 'service', 'instance'] as $name) {
      $value = $options[$name] ?? null;
      if (is_string($value)) {
        $this->constLabels[$name] = $value;
      }
    }
    $exclude = $options['exclude'] ?? null;
    if (is_array($exclude)) {
      foreach ($exclude as $name) {
        if (is_string($name) && $name !== '') {
          $this->exclude[$name] = true;
        }
      }
    }
    $include = $options['include'] ?? null;
    if (is_array($include)) {
      foreach ($include as $name) {
        if (is_string($name) && $name !== '') {
          $this->include[$name] = true;
        }
      }
    }
    $pushUrl = $options['push_url'] ?? null;
    if (is_string($pushUrl)) {
      self::validatePushUrl($pushUrl);
      $this->pushUrl = $pushUrl;
    } elseif ($pushUrl !== null) {
      throw new InvalidArgumentException('push_url must be an http or https URL');
    }
    $timeout = $options['timeout_sec'] ?? null;
    if (is_int($timeout) || is_float($timeout)) {
      $timeout = (float)$timeout;
      if ($timeout > 0) {
        $this->timeoutSec = $timeout;
      }
    } elseif (is_string($timeout) && is_numeric($timeout)) {
      $timeout = (float)$timeout;
      if ($timeout > 0) {
        $this->timeoutSec = $timeout;
      }
    }
    $interval = $options['push_interval_sec'] ?? null;
    if (is_int($interval) || is_float($interval)) {
      $interval = (float)$interval;
      $this->pushIntervalSec = $interval > 0 ? $interval : 0.0;
    } elseif (is_string($interval) && is_numeric($interval)) {
      $interval = (float)$interval;
      $this->pushIntervalSec = $interval > 0 ? $interval : 0.0;
    }
    $shutdown = $options['push_on_shutdown'] ?? true;
    if ($shutdown) {
      $self = $this;
      register_shutdown_function(function () use ($self): void {
        $self->push();
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
      $this->logMirror($metric . ': ' . $e->getMessage());
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
      $this->logMirror($metric . ': ' . $e->getMessage());
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
    if (!$this->enabled || ($this->counterSeries === [] && $this->histogramSeries === [])) {
      return '';
    }
    $lines = [];
    foreach ($this->counterSeries as $name => $keys) {
      if (!is_string($name)) {
        continue;
      }
      $lines[] = '# HELP ' . $name . ' StatsHouse counter mirrored to Prometheus';
      $lines[] = '# TYPE ' . $name . ' counter';
      $ordered = $keys;
      sort($ordered, SORT_STRING);
      foreach ($ordered as $key) {
        if (!is_string($key)) {
          continue;
        }
        $id = $this->storeKey($name, $key);
        if (isset($this->seriesLabels[$id], $this->counterValue[$id])) {
          $lines[] = $this->sampleLine($name, $this->seriesLabels[$id], $this->counterValue[$id]);
        }
      }
    }
    foreach ($this->histogramSeries as $name => $keys) {
      if (!is_string($name)) {
        continue;
      }
      $lines[] = '# HELP ' . $name . ' StatsHouse value mirrored as histogram';
      $lines[] = '# TYPE ' . $name . ' histogram';
      $ordered = $keys;
      sort($ordered, SORT_STRING);
      foreach ($ordered as $key) {
        if (!is_string($key)) {
          continue;
        }
        $id = $this->storeKey($name, $key);
        if (!isset($this->seriesLabels[$id], $this->histogramCount[$id], $this->histogramSum[$id])) {
          continue;
        }
        $labels = $this->seriesLabels[$id];
        $accumulated = 0.0;
        foreach (self::VALUE_BUCKETS as $edge) {
          $bound = (string)$edge;
          $bucketId = $id . "\0" . $bound;
          if (isset($this->histogramBucket[$bucketId])) {
            $accumulated += $this->histogramBucket[$bucketId];
          }
          $bucketLabels = $labels;
          $bucketLabels['le'] = $bound;
          $lines[] = $this->sampleLine($name . '_bucket', $bucketLabels, $accumulated);
        }
        $infId = $id . "\0+Inf";
        if (isset($this->histogramBucket[$infId])) {
          $accumulated += $this->histogramBucket[$infId];
        }
        $bucketLabels = $labels;
        $bucketLabels['le'] = '+Inf';
        $lines[] = $this->sampleLine($name . '_bucket', $bucketLabels, $accumulated);
        $lines[] = $this->sampleLine($name . '_count', $labels, $this->histogramCount[$id]);
        $lines[] = $this->sampleLine($name . '_sum', $labels, $this->histogramSum[$id]);
      }
    }
    return implode("\n", $lines) . "\n";
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
      if ($this->pushUrl !== '' && !$this->httpPost($body)) {
        $this->logMirror('push failed');
        return;
      }
      $this->dirty = false;
      $this->clearSamples();
    } catch (Throwable $e) {
      $this->logMirror('push failed: ' . $e->getMessage());
    }
  }

  /**
   * @param array $keys
   */
  private function mirrorCount(string $metric, $keys, float $count): void {
    if (!$this->shouldMirror($metric) || !is_finite($count) || $count <= 0) {
      return;
    }
    $name = $this->sanitizeMetric($metric);
    $labels = $this->labelMap($keys);
    if ($name === null || $labels === null) {
      return;
    }
    $full = self::NAMESPACE . '_' . $name;
    $this->rememberLabels($this->counterLabels, $full, $labels);
    $key = $this->seriesKey($labels);
    $id = $this->storeKey($full, $key);
    if (!isset($this->counterValue[$id])) {
      if (!isset($this->counterSeries[$full])) {
        $this->counterSeries[$full] = [];
      }
      $this->counterSeries[$full][] = $key;
      $this->seriesLabels[$id] = $labels;
      $this->counterValue[$id] = 0.0;
    }
    $this->counterValue[$id] += $count;
    $this->dirty = true;
  }

  /**
   * @param array $keys
   * @param array $values
   */
  private function mirrorValue(string $metric, $keys, $values): void {
    if (!$this->shouldMirror($metric)) {
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
    if ($name === null || $labels === null) {
      return;
    }
    if (in_array('le', array_keys($labels), true)) {
      throw new InvalidArgumentException("Histogram cannot have a label named 'le'.");
    }
    $full = self::NAMESPACE . '_' . $name;
    $this->rememberLabels($this->histogramLabels, $full, $labels);
    $key = $this->seriesKey($labels);
    $id = $this->storeKey($full, $key);
    if (!isset($this->histogramSum[$id])) {
      if (!isset($this->histogramSeries[$full])) {
        $this->histogramSeries[$full] = [];
      }
      $this->histogramSeries[$full][] = $key;
      $this->seriesLabels[$id] = $labels;
      $this->histogramSum[$id] = 0.0;
      $this->histogramCount[$id] = 0.0;
    }
    foreach ($finite as $value) {
      $bound = '+Inf';
      foreach (self::VALUE_BUCKETS as $edge) {
        if ($value <= $edge) {
          $bound = (string)$edge;
          break;
        }
      }
      $bucketId = $id . "\0" . $bound;
      $bucket = $this->histogramBucket[$bucketId] ?? 0.0;
      $this->histogramBucket[$bucketId] = $bucket + 1.0;
      $this->histogramSum[$id] += $value;
      $this->histogramCount[$id] += 1.0;
    }
    $this->dirty = true;
  }

  private function storeKey(string $full, string $seriesKey): string {
    return $full . "\0" . $seriesKey;
  }

  private function shouldMirror(string $metric): bool {
    if (!$this->enabled || $metric === '') {
      return false;
    }
    if ($this->include !== []) {
      return isset($this->include[$metric]);
    }
    return !isset($this->exclude[$metric]);
  }

  private function logMirror(string $message): void {
    $line = strstr($message, "\n", true);
    $text = 'statshouse mirror: ' . (is_string($line) ? $line : $message);
    warning($text);
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
    $cleaned = preg_replace('/[^a-zA-Z0-9_:]/', '_', $metric);
    if (!is_string($cleaned) || $cleaned === '') {
      return null;
    }
    $name = $cleaned;
    if (preg_match('/^[a-zA-Z_:][a-zA-Z0-9_:]*$/', self::NAMESPACE . '_' . $name) !== 1) {
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
    if (!is_string($key)) {
      return '';
    }
    if (strlen($key) >= 2 && $key[0] === '_' && is_numeric($key[1])) {
      $tail = substr($key, 1);
      return is_string($tail) ? $tail : $key;
    }
    return $key;
  }

  private function sanitizeLabel(string $name): ?string {
    if ($name === '') {
      return null;
    }
    if (preg_match('/^[0-9]+$/', $name) === 1) {
      $name = 'tag_' . $name;
    }
    $cleaned = preg_replace('/[^a-zA-Z0-9_]/', '_', $name);
    if (!is_string($cleaned) || $cleaned === '') {
      return null;
    }
    $name = $cleaned;
    if (preg_match('/^[a-zA-Z_]/', $name) !== 1) {
      $name = '_' . $name;
    }
    if (preg_match('/^[a-zA-Z_][a-zA-Z0-9_]*$/', $name) !== 1 || strpos($name, '__') === 0) {
      return null;
    }
    return $name;
  }

  /**
   * @param array<string, string[]> $known
   * @param array<string, string> $labels
   */
  private function rememberLabels(array &$known, string $name, array $labels): void {
    $names = [];
    foreach ($labels as $label => $labelValue) {
      if (is_string($label) && is_string($labelValue)) {
        $names[] = $label;
      }
    }
    if (!isset($known[$name])) {
      $known[$name] = $names;
      return;
    }
    if (count($names) !== count($known[$name])) {
      throw new InvalidArgumentException(sprintf('Labels are not defined correctly: %s', print_r(array_values($labels), true)));
    }
  }

  /**
   * @param array<string, string> $labels
   */
  private function seriesKey(array $labels): string {
    $key = json_encode($labels);
    return is_string($key) ? $key : '';
  }

  /**
   * @param array $labels
   */
  private function sampleLine(string $name, array $labels, float $value): string {
    if (count($labels) === 0) {
      return $name . ' ' . $this->formatNumber($value);
    }
    $parts = [];
    foreach ($labels as $label => $labelValue) {
      if (!is_string($label) || !is_string($labelValue)) {
        continue;
      }
      $parts[] = $label . '="' . $this->escapeLabelValue($labelValue) . '"';
    }
    if ($parts === []) {
      return $name . ' ' . $this->formatNumber($value);
    }
    return $name . '{' . implode(',', $parts) . '} ' . $this->formatNumber($value);
  }

  private function formatNumber(float $value): string {
    $text = sprintf('%.16F', $value);
    $text = rtrim(rtrim($text, '0'), '.');
    return $text === '' || $text === '-' ? '0' : $text;
  }

  private function escapeLabelValue(string $value): string {
    return str_replace(["\\", "\n", "\""], ["\\\\", "\\n", "\\\""], $value);
  }

  private function clearSamples(): void {
    $this->counterSeries = [];
    $this->counterValue = [];
    $this->counterLabels = [];
    $this->histogramSeries = [];
    $this->histogramSum = [];
    $this->histogramCount = [];
    $this->histogramBucket = [];
    $this->histogramLabels = [];
    $this->seriesLabels = [];
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
    $scheme = '';
    $host = '';
    if (is_array($parts)) {
      $schemeRaw = $parts['scheme'] ?? '';
      $hostRaw = $parts['host'] ?? '';
      if (is_string($schemeRaw)) {
        $scheme = strtolower($schemeRaw);
      }
      if (is_string($hostRaw)) {
        $host = $hostRaw;
      }
    }
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
    $timeoutMs = (int)max(1, (int)round($this->timeoutSec * 1000));
    if (!curl_setopt($ch, CURLOPT_POST, 1)) {
      return false;
    }
    if (!curl_setopt($ch, CURLOPT_POSTFIELDS, $body)) {
      return false;
    }
    if (!curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: ' . self::TEXT_MIME])) {
      return false;
    }
    if (!curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1)) {
      return false;
    }
    if (!curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0)) {
      return false;
    }
    if (!curl_setopt($ch, CURLOPT_TIMEOUT_MS, $timeoutMs)) {
      return false;
    }
    if (!curl_setopt($ch, CURLOPT_CONNECTTIMEOUT_MS, $timeoutMs)) {
      return false;
    }
    $result = curl_exec($ch);
    $info = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $code = -1;
    if (is_int($info)) {
      $code = $info;
    } elseif (is_float($info) || (is_string($info) && is_numeric($info))) {
      $code = (int)$info;
    }
    return $result !== false && $result !== null && $code >= 200 && $code < 300;
  }

  private function postStream(string $body): bool {
#ifndef KPHP
    if ($this->pushUrl === '') {
      return false;
    }
    $context = stream_context_create([
      'http' => [
        'method' => 'POST',
        'header' => 'Content-Type: ' . self::TEXT_MIME . "\r\n",
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
#endif
    return strlen($body) < 0;
  }
}
