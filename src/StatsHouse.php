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

  private const TCP_HEADER               = "statshousev1";
  private const DNS_REFRESH_INTERVAL_SEC = 60.0;
  private const DNS_REFRESH_TIMEOUT_SEC  = 3;

  /** @var string|false|mixed $udp_socket */
  private $udp_socket                = false;
  /** @var string|false|mixed $tcp_primary_socket */
  private $tcp_primary_socket        = false;
  /** @var string|false|mixed $tcp_secondary_socket */
  private $tcp_secondary_socket      = false;
  private string $packet             = '';
  private bool $immediate_flush      = false;
  private bool $shutdown_registered  = false;
  private string $addr;
  private string $network            = 'udp';
  private string $host_tag           = '';
  /** @var string[] */
  private array $dial_targets        = [];
  private int $tcp_head              = 0;
  private float $last_flush_ts       = 0;
  private float $last_dns_refresh_ts = 0;

  public function __construct(string $addr) {
    $this->addr = $addr;
    $this->network = self::detectNetwork($addr);
    $this->host_tag = (string)gethostname();
    $this->dial_targets = self::resolveDialTargetsSync($this->network, $addr);
    $this->last_dns_refresh_ts = (float)microtime(true);
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
    $parts = explode(',', $addr);
    if (count($parts) === 0) {
      return 'udp';
    }
    $network = strtolower((string)parse_url($parts[0], PHP_URL_SCHEME));
    if ($network === 'tcp' || $network === 'udp' || $network === 'unixgram') {
      return $network;
    }
    return 'udp';
  }

  /** @return string[] */
  private static function resolveDialTargetsSync(string $network, string $addr): array {
    if ($addr === '') {
      return [];
    }
    if ($network === 'unixgram') {
      return [$addr];
    }

    $targets = explode(',', $addr);
    if (count($targets) === 0) {
      return [];
    }
    if ($network === 'udp') {
      // For UDP we intentionally keep DNS names unresolved and dial hostnames directly.
      return $targets;
    }

    $resolved = [];
    for ($i = 0; $i < count($targets); $i++) {
      $host = (string)parse_url($targets[$i], PHP_URL_HOST);
      $port = (int)parse_url($targets[$i], PHP_URL_PORT);
      if ($host === '' || $port <= 0) {
        continue;
      }
      if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
        $resolved[] = $network . '://' . $host . ':' . $port;
        continue;
      }

      $ips = self::resolveHostIPv4($host);
      for ($j = 0; $j < count($ips); $j++) {
        $resolved[] = $network . '://' . $ips[$j] . ':' . $port;
      }
    }
    if (count($resolved) === 0) {
      return $targets;
    }
    return $resolved;
  }

  /**
   * Best-effort host resolve with optional soft timeout budget.
   * Note: PHP DNS functions do not provide strict per-call cancellation.
   *
   * @return string[]
   */
  private static function resolveHostIPv4(string $host): array {
    @ini_set('default_socket_timeout', (string)self::DNS_REFRESH_TIMEOUT_SEC);
    $ips = gethostbynamel($host);
    if ($ips !== false) {
      return $ips;
    }
    $single = gethostbyname($host);
    if ($single !== $host) {
      return [$single];
    }
    return [];
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

  private function maybeRefreshTcpDns(float $now): void {
    if ($this->network !== 'tcp') {
      return;
    }
    if ($now < $this->last_dns_refresh_ts + self::DNS_REFRESH_INTERVAL_SEC) {
      return;
    }
    $this->dial_targets = self::resolveDialTargetsSync($this->network, $this->addr);
    $this->last_dns_refresh_ts = $now;
    $this->tcp_head = 0;
  }

  private function maybeConnectUdp(): ?string {
    if ($this->udp_socket) {
      return null;
    }
    $targets = $this->dial_targets;
    if (count($targets) === 0) {
      $targets = explode(',', $addr);
    }
    if (count($targets) === 0) {
      return 'empty statshouse address';
    }
    $dialAddr = $targets[0];
    $error_code    = 0;
    $error_message = '';
    $sock = stream_socket_client($dialAddr, $error_code, $error_message); // KPHP does not have fsockopen
    if ($sock === false) {
      return "$error_message (code $error_code)";
    }

    // earlier versions of KPHP thought $sock is mixed, not string|false, so we had #ifndef KPHP here
    // in PHP, $sock is resource, but that does not matter as annotations are skipped
    $this->udp_socket = $sock;
    return null;
  }

  private function writeTcp(string $payload): bool {
    if (!$this->writeTcpByRole('primary', $payload)) {
      if (!$this->writeTcpByRole('secondary', $payload)) {
        return false;
      }
      $this->swapTcpSockets();
    }
    $this->ensureSecondaryConnected();
    return true;
  }

  private function writeTcpByRole(string $role, string $payload): bool {
    $sock = ($role === 'primary') ? $this->tcp_primary_socket : $this->tcp_secondary_socket;
    if (!$sock) {
      $err = $this->reconnectTcp($role);
      if ($err !== null) {
        return false;
      }
      $sock = ($role === 'primary') ? $this->tcp_primary_socket : $this->tcp_secondary_socket;
    }
    $ok = @fwrite($sock, $payload);
    if ($ok !== false) {
      return true;
    }
    @fclose($sock);
    if ($role === 'primary') {
      $this->tcp_primary_socket = false;
    } else {
      $this->tcp_secondary_socket = false;
    }
    return false;
  }

  private function ensureSecondaryConnected(): void {
    if ($this->tcp_secondary_socket) {
      return;
    }
    $this->reconnectTcp('secondary');
  }

  private function reconnectTcp(string $role): ?string {
    $pool = $this->dial_targets;
    if (count($pool) === 0) {
      return 'empty statshouse address';
    }

    $idx = $this->tcp_head;
    $tried = 0;
    while ($tried < count($pool)) {
      $addr = $pool[$idx];
      $error_code = 0;
      $error_message = '';
      $sock = stream_socket_client($addr, $error_code, $error_message, 5.0);
      $idx = ($idx + 1) % count($pool);
      $tried++;
      if ($sock === false) {
        continue;
      }
      $ok = @fwrite($sock, self::TCP_HEADER);
      if ($ok === false) {
        @fclose($sock);
        continue;
      }
      $this->tcp_head = $idx;
      if ($role === 'primary') {
        $this->tcp_primary_socket = $sock;
      } else {
        $this->tcp_secondary_socket = $sock;
      }
      return null;
    }
    return 'failed to dial statshouse';
  }

  private function swapTcpSockets(): void {
    $tmp = $this->tcp_primary_socket;
    $this->tcp_primary_socket = $this->tcp_secondary_socket;
    $this->tcp_secondary_socket = $tmp;
  }

  private function flush(string $metric, float $now, bool $close_after): ?string {
    if ($this->network === 'tcp') {
      $this->maybeRefreshTcpDns($now);
      $tcpPayload = pack('V', strlen($this->packet)) . $this->packet;
      if (!$this->writeTcp($tcpPayload)) {
        $this->packet = '';
        return "$metric: write failed";
      }

      if ($close_after) {
        if ($this->tcp_primary_socket) {
          @fclose($this->tcp_primary_socket);
          $this->tcp_primary_socket = false;
        }
        if ($this->tcp_secondary_socket) {
          @fclose($this->tcp_secondary_socket);
          $this->tcp_secondary_socket = false;
        }
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
}
