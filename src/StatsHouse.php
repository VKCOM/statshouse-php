<?php
// Copyright 2022 V Kontakte LLC
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

declare(strict_types = 1);
/** @kphp-strict-types-enabled */

namespace VK\StatsHouse;

/**
 * New TL-based statshouse transport layer.
 * All strings must be in utf-8 encoding.
 *
 * All aggregation is performed by StatsHouse daemon.
 * Aggregation type is determined by StatsHouse daemon according to stat configuration.
 */
class StatsHouse {
  /**
   * IPv6 mandated minimum MTU size of 1280
   * (minus 40 byte IPv6 header and 8 byte UDP header)
   */
  private const MAX_PAYLOAD_SIZE = 1232;

  private const MAX_STRING_LEN         = 128;

  private const TL_LEN_SIZE            = 4;
  private const TL_LONG_SIZE           = 8;
  private const TL_DOUBLE_SIZE         = 8;
  private const TL_MAX_TINY_STRING_LEN = 253;
  private const TL_BIG_STRING_MARKER   = 0xfe;
  private const TL_STRING_PAD          = "\0\0\0";

  private const ERR_HEADER_TOO_BIG     = 'Metric name and tags are too big';

  private const TL_STATSHOUSE_METRICS_BATCH_TAG           = 0x56580239;
  private const TL_STATSHOUSE_METRIC_COUNTER_FIELDS_MASK  = 1 << 0;
  private const TL_STATSHOUSE_METRIC_TS_FIELDS_MASK       = 1 << 4;
  private const TL_STATSHOUSE_METRIC_VALUE_FIELDS_MASK    = 1 << 1;
  private const TL_STATSHOUSE_METRIC_UNIQUE_FIELDS_MASK   = 1 << 2;

  private const RARE_LOG_INTERVAL_SEC    = 1.0;

  /** @var string|false|mixed $udp_socket */
  private $udp_socket                = false;
  /** @var string|false|mixed $unix_socket */
  private $unix_socket               = false;
  private string $unix_pending       = '';
  private int $unix_would_block_bytes = 0;
  private string $packet             = '';
  private bool $immediate_flush      = false;
  private bool $shutdown_registered  = false;
  private string $addr;
  private string $network            = 'udp';
  private string $host_tag           = '';
  private string $app_tag            = '';
  private float $last_flush_ts       = 0;
  private float $last_rare_log_ts    = 0;

  public function __construct(string $addr, string $application = 'mono') {
    $this->addr = $addr;
    $this->network = self::detectNetwork($addr);
    $this->host_tag = (string)gethostname();
    $this->app_tag = $application;
  }

  /**
   * @kphp-warn-unused-result
   * @param string[] $keys
   */
  public function writeCount(string $metric, $keys, float $count, int $ts): ?string {
    $now = (float)microtime(true);
    $head = self::packHeader($metric, $this->addSystemTags($keys), $count, $ts, self::TL_STATSHOUSE_METRIC_COUNTER_FIELDS_MASK);
    if (strlen($head) > self::MAX_PAYLOAD_SIZE) {
      return self::ERR_HEADER_TOO_BIG;
    }
    if (strlen($this->packet) + strlen($head) > self::MAX_PAYLOAD_SIZE) {
      $err = $this->flush($metric, $now, false);
      if ($err !== null) {
        return $err;
      }
    }
    $this->packet .= $head;
    return $this->maybeFlush($metric, $now);
  }

  /**
   * @kphp-warn-unused-result
   * @param string[] $keys
   * @param float[] $values
   */
  public function writeValue(string $metric, $keys, $values, float $count, int $ts): ?string {
    $total = count($values);
    if ($total === 0) {
      return null;
    }
    $fields_mask = self::TL_STATSHOUSE_METRIC_VALUE_FIELDS_MASK;
    if ($count != 0.0 && $count != count($values)) {
      $fields_mask |= self::TL_STATSHOUSE_METRIC_COUNTER_FIELDS_MASK;
    }
    $now = (float)microtime(true);
    $head = self::packHeader($metric, $this->addSystemTags($keys), $count, $ts, $fields_mask);
    for ($pos = 0; $pos < $total;) {
      $start_pos = $pos;
      $remaining_space = self::MAX_PAYLOAD_SIZE - strlen($this->packet) - strlen($head) - self::TL_LEN_SIZE;
      if ($remaining_space < self::TL_DOUBLE_SIZE) {
        $remaining_space = self::MAX_PAYLOAD_SIZE - strlen($head) - self::TL_LEN_SIZE;
        if ($remaining_space < self::TL_DOUBLE_SIZE) {
          return self::ERR_HEADER_TOO_BIG;
        }
        $err = $this->flush($metric, $now, false); // either clears body or returns error
        if ($err !== null) {
          return $err;
        }
      }
      $body = '';
      for (; $pos < $total && $remaining_space >= self::TL_DOUBLE_SIZE; $pos++) {
        $body .= pack('d', $values[$pos]); // format should be 'e', but KPHP only knows about 'd' :-(
        $remaining_space -= self::TL_DOUBLE_SIZE;
      }
      $this->packet .= $head;
      $this->packet .= pack('V', $pos - $start_pos);
      $this->packet .= $body;
    }
    return $this->maybeFlush($metric, $now);
  }

  /**
   * @kphp-warn-unused-result
   * @param string[] $keys
   * @param int[] $values
   */
  public function writeUnique(string $metric, $keys, $values, float $count, int $ts): ?string {
    $total = count($values);
    if ($total === 0) {
      return null;
    }
    $fields_mask = self::TL_STATSHOUSE_METRIC_UNIQUE_FIELDS_MASK;
    if ($count != 0.0 && $count != count($values)) {
      $fields_mask |= self::TL_STATSHOUSE_METRIC_COUNTER_FIELDS_MASK;
    }
    $now = (float)microtime(true);
    $head = self::packHeader($metric, $this->addSystemTags($keys), $count, $ts, $fields_mask);
    for ($pos = 0; $pos < $total;) {
      $start_pos = $pos;
      $remaining_space = self::MAX_PAYLOAD_SIZE - strlen($this->packet) - strlen($head) - self::TL_LEN_SIZE;
      if ($remaining_space < self::TL_LONG_SIZE) {
        $remaining_space = self::MAX_PAYLOAD_SIZE - strlen($head) - self::TL_LEN_SIZE;
        if ($remaining_space < self::TL_LONG_SIZE) {
          return self::ERR_HEADER_TOO_BIG;
        }
        $err = $this->flush($metric, $now, false); // either clears body or returns error
        if ($err !== null) {
          return $err;
        }
      }
      $body = '';
      for (; $pos < $total && $remaining_space >= self::TL_LONG_SIZE; $pos++) {
        $body .= pack('P', $values[$pos]);
        $remaining_space -= self::TL_LONG_SIZE;
      }
      $this->packet .= $head;
      $this->packet .= pack('V', $pos - $start_pos);
      $this->packet .= $body;
    }
    return $this->maybeFlush($metric, $now);
  }

  /**
   * Advanced feature.
   * Encodes float as a raw tag in a special format, used by Statshouse.
   * Ordering of all float values is preserved after encoding.
   * Except all NaNs map to single value which is > +inf, and both zeroes map to 0.
   */
  public static function lexEncFloat(float $f): int {
    if (is_nan($f)) {
      return 0x7fc00000; // replace all NaNs with single positive quiet NaN
    }
    if ($f == 0) {
      return 0; // replace -0 with +0
    }
    $data = pack('f', $f);
    $arr = unpack('l', $data);
    if ($arr === false) {
      return 0; // never
    }
    $l = (int)$arr[1];
    if ($l < 0) {
      $l ^= 0x7fffffff; // flip all except signbit so bigger negatives go before smaller ones
    }
    return $l;
  }
  public static function lexDecFloat(int $l): float {
    if ($l < 0) {
      $l ^= 0x7fffffff;
    }
    $data = pack('l', $l);
    $arr = unpack('f', $data);
    if ($arr === false) {
      return 0; // never
    }
    return (float)$arr[1];
  }

  /**
   * All integer array indexes will be replaced by 'key'.($k+1)
   * String keys will be left as is
   *
   * @param string[] $keys
   */
  private static function packHeader(string $metric, $keys, float $count, int $ts, int $fields_mask): string {
    // we hope that KPHP can inline trivial packs
    $data  = pack('V', self::TL_STATSHOUSE_METRICS_BATCH_TAG);
    $data .= pack('V', 0); // fields mask
    $data .= pack('V', 1); // batch size
    if ($ts !== 0) {
      $fields_mask |= self::TL_STATSHOUSE_METRIC_TS_FIELDS_MASK;
    }
    $data .= pack('V', $fields_mask); // metric fields mask
    $data .= self::packShortString($metric);
    $data .= pack('V', count($keys));
    foreach ($keys as $k => $v) {
      if (is_int($k)) { // for common arrays of type ['a', 'b', 'c']
        $data .= self::packShortString(''.($k+1));
      } else { // for arrays of type [ '_1' => 'a', '_2' => 'b', '_7' => 'c']
        $sk = (string)$k;
        $le = strlen($sk);
        if ($le >= 2 && $sk[0] === '_' && is_numeric($sk[1])) { // replace _1, but not _s, _h, etc.
          $data .= self::packShortString((string)substr($sk,1));
        } else {
          $data .= self::packShortString($sk);
        }
      }
      $data .= self::packShortString($v);
    }
    if (($fields_mask & self::TL_STATSHOUSE_METRIC_COUNTER_FIELDS_MASK) !== 0) {
      $data .= pack('d', $count);
    }
    if (($fields_mask & self::TL_STATSHOUSE_METRIC_TS_FIELDS_MASK) !== 0) {
      $data .= pack('V', $ts);
    }
    return $data;
  }

  private static function tlPadSize(int $n): int {
    $r = $n % 4;
    return $r === 0 ? 0 : 4 - $r;
  }

  /**
   * @param string $s must be shorter than 1<<24 (maximum TL string length)
   */
  private static function packShortString(string $s): string {
    $n = strlen($s);
    if ($n > self::MAX_STRING_LEN) { // otherwise, metric might not fit into packet.
      $n = self::MAX_STRING_LEN;
    }
    $data = '';
    /** @phpstan-ignore-next-line */
    if ($n <= self::TL_MAX_TINY_STRING_LEN) {
      $data .= pack('C', $n);
      /** @phpstan-ignore-next-line */
    } else {
      /** @note Keep as example of processing long string. */
      $data .= pack('V', ($n << 8) | self::TL_BIG_STRING_MARKER); // no check for overflow
    }
    $data .= substr($s, 0, $n);
    $p = self::tlPadSize(strlen($data));
    $data .= substr(self::TL_STRING_PAD, 0, $p);
    return $data;
  }

  private static function detectNetwork(string $addr): string {
    if (strpos($addr, 'unix://') === 0) {
      return 'unix';
    }
    if (strpos($addr, 'udp://') === 0) {
      return 'udp';
    }
    $network = strtolower((string)parse_url($addr, PHP_URL_SCHEME));
    if ($network === 'udp' || $network === 'unix') {
      return $network;
    }
    return 'udp';
  }

  /**
   * @param string[] $keys
   * @return string[]
   */
  private function addSystemTags($keys): array {
    if ($this->host_tag !== '' && !array_key_exists('_h', $keys)) {
      $keys['_h'] = $this->host_tag;
    }
    return $keys;
  }

  private function maybeConnectUdp(): ?string {
    if ($this->udp_socket) {
      return null;
    }

    $error_code    = 0;
    $error_message = '';
    $sock = stream_socket_client($this->addr, $error_code, $error_message); // KPHP does not have fsockopen
    if ($sock === false) {
      $this->rareLog("failed to dial statshouse via udp: $error_message (code $error_code)");
      return "$error_message (code $error_code)";
    }

    // earlier versions of KPHP thought $sock is mixed, not string|false, so we had #ifndef KPHP here
    // in PHP, $sock is resource, but that does not matter as annotations are skipped
    $this->udp_socket = $sock;
    return null;
  }

  private function writeUnix(string $payload): bool {
    $this->flushUnixPending();
    if ($this->unix_pending !== '') {
      $this->unix_would_block_bytes += strlen($payload);
      return false;
    }
    if ($this->writeUnixSocket($payload)) {
      $this->reportWouldBlockIfAny();
      return true;
    }
    $this->unix_would_block_bytes += strlen($payload);
    return false;
  }

  private function flushUnixPending(): void {
    if ($this->unix_pending === '') {
      return;
    }
    $this->writeUnixSocket('');
  }

  private function writeUnixSocket(string $payload): bool {
    $sock = $this->unix_socket;
    if (!$sock) {
      $err = $this->reconnectUnix();
      if ($err !== null) {
        $this->rareLog("failed to reconnect statshouse unix socket: $err");
        return false;
      }
      $sock = $this->unix_socket;
    }
    $written = 0;
    $buffer = $this->unix_pending . $payload;
    $len = strlen($buffer);
    while ($written < $len) {
      $n = @fwrite($sock, substr($buffer, $written));
      if ($n === false) {
        $this->rareLog('failed to send data to statshouse via unix socket');
        @fclose($sock);
        $this->unix_socket = false;
        if ($written > 0) {
          $this->unix_pending = substr($buffer, $written);
          return true;
        }
        return false;
      }
      if ($n === 0) {
        break;
      }
      $written += $n;
    }
    if ($written >= $len) {
      $this->unix_pending = '';
      return true;
    }
    $this->unix_pending = substr($buffer, $written);
    return true;
  }

  private function reconnectUnix(): ?string {
    if ($this->unix_pending !== '') {
      $this->unix_would_block_bytes += strlen($this->unix_pending);
      $this->unix_pending = '';
    }
    if ($this->addr === '') {
      return 'empty statshouse address';
    }
    $error_code = 0;
    $error_message = '';
    $flags = STREAM_CLIENT_CONNECT;
    $sock = stream_socket_client($this->addr, $error_code, $error_message, 0.0, $flags);
    if ($sock === false) {
      $this->rareLog("failed to dial statshouse via unix: $error_message (code $error_code)");
      return "$error_message (code $error_code)";
    }
    @stream_set_blocking($sock, false);
    $this->unix_socket = $sock;
    $this->unix_pending = '';
    return null;
  }

  private function reportWouldBlockIfAny(): void {
    if ($this->unix_would_block_bytes <= 0) {
      return;
    }
    $n = $this->unix_would_block_bytes;
    $this->unix_would_block_bytes = 0;
    $this->rareLog("lost $n bytes");
    $this->writeCount('__src_client_write_err', [
      '1' => '4', // lang: php
      '2' => '1', // kind: would block
      '3' => $this->app_tag,
    ], (float)$n, 0);
  }

  private function flush(string $metric, float $now, bool $close_after): ?string {
    if ($this->network === 'unix') {
      $unixPayload = pack('V', strlen($this->packet)) . $this->packet;
      if (!$this->writeUnix($unixPayload)) {
        $this->packet = '';
        return "$metric: write failed";
      }

      if ($close_after) {
        if ($this->unix_socket) {
          @fclose($this->unix_socket);
          $this->unix_socket = false;
        }
        $this->unix_pending = '';
      }

      $this->last_flush_ts = $now;
      $this->packet = '';
      return null;
    }

    $err = $this->maybeConnectUdp();
    if ($err !== null) {
      return "$metric: failed to connect: $err";
    }

    $ok = @fwrite($this->udp_socket, $this->packet);
    if ($ok === false || $close_after) {
      @fclose($this->udp_socket);
      $this->udp_socket = false;
    }

    if ($ok === false) {
      return "$metric: write failed";
    }
    $this->last_flush_ts = $now;
    $this->packet = '';
    return null;
  }

  private function maybeFlush(string $metric, float $now): ?string {
    if ($this->immediate_flush) {
      return $this->flush($metric, $now, true);
    }

    if (!$this->shutdown_registered) {
      $this->shutdown_registered = true;
      register_shutdown_function(function() use ($metric) {
        $this->immediate_flush = true; // for statshouse from other shutdown functions
        $this->flush("deferred $metric", (float)microtime(true), true);
      });
    }

    if ($this->packet != '' && $now > $this->last_flush_ts + 0.25) {
      // TODO - if no activity, timestamps will be wrong. Should we set timestamps per metric?
      return $this->flush($metric, $now, false);
    }
    return null;
  }

  private function rareLog(string $message): void {
    $now = (float)microtime(true);
    if ($now < $this->last_rare_log_ts + self::RARE_LOG_INTERVAL_SEC) {
      return;
    }
    $this->last_rare_log_ts = $now;
    error_log("[statshouse] $message");
  }
}
