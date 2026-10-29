'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  TARGETS, splitUris, parseVlessUri, buildVlessUri, normalizeAuthority, toFileName,
} = require('../web/qr/vless.js');

const SAMPLE = 'vless://2898f95d-52cb-43de-8603-d72b9c01bc88@vpnus.puton.top:8444'
  + '?encryption=none&extra=%7B%22mode%22%3A%22auto%22%7D&host=vpnus.puton.top&mode=auto'
  + '&path=%2Fwarp&security=none&type=xhttp#VLESS-XHTTP-WARP-8444-TestWARP';

test('splitUris separates URIs on any whitespace and drops blanks', () => {
  assert.deepEqual(splitUris(`\n ${SAMPLE}\n\n\t${SAMPLE}  x \n`), [SAMPLE, SAMPLE, 'x']);
  assert.deepEqual(splitUris('   \n '), []);
});

test('parseVlessUri splits the 3x-ui sample', () => {
  const parsed = parseVlessUri(SAMPLE);
  assert.equal(parsed.ok, true);
  assert.equal(parsed.userInfo, '2898f95d-52cb-43de-8603-d72b9c01bc88');
  assert.equal(parsed.authority, 'vpnus.puton.top:8444');
  assert.ok(parsed.tail.startsWith('?encryption=none'));
  assert.ok(parsed.tail.endsWith('type=xhttp'));
  assert.equal(parsed.label, 'VLESS-XHTTP-WARP-8444-TestWARP');
});

test('buildVlessUri round-trips an unchanged URI', () => {
  assert.equal(buildVlessUri(parseVlessUri(SAMPLE)), SAMPLE);
});

test('buildVlessUri swaps only host:port and keeps the host= query value', () => {
  const uri = buildVlessUri(parseVlessUri(SAMPLE), { authority: TARGETS.vina0d.authority });
  assert.ok(uri.startsWith('vless://2898f95d-52cb-43de-8603-d72b9c01bc88@vina.puton.top:443?'));
  assert.ok(uri.includes('&host=vpnus.puton.top&'));
  assert.ok(uri.endsWith('#VLESS-XHTTP-WARP-8444-TestWARP'));
});

test('buildVlessUri encodes an edited label', () => {
  const uri = buildVlessUri(parseVlessUri(SAMPLE), { authority: TARGETS.tiktok.authority, label: 'Nhà #1' });
  assert.ok(uri.includes('@api24-normal-alisg.tiktokv.com:443?'));
  assert.ok(uri.endsWith('#Nh%C3%A0%20%231'));
  assert.equal(parseVlessUri(uri).label, 'Nhà #1');
});

test('buildVlessUri drops the fragment for an empty label', () => {
  assert.ok(!buildVlessUri(parseVlessUri(SAMPLE), { label: '' }).includes('#'));
});

test('parseVlessUri uses the last # as the label separator', () => {
  const parsed = parseVlessUri('vless://id@h.example:443?path=%2F#a#b');
  assert.equal(parsed.ok, true);
  assert.equal(parsed.tail, '?path=%2F#a');
  assert.equal(parsed.label, 'b');
});

test('parseVlessUri keeps a malformed percent-encoded label as typed', () => {
  assert.equal(parseVlessUri('vless://id@h.example:443#100%').label, '100%');
});

test('parseVlessUri accepts IPv6 hosts and URIs without query or label', () => {
  const parsed = parseVlessUri('vless://id@[2001:db8::1]:8443');
  assert.equal(parsed.ok, true);
  assert.equal(parsed.authority, '[2001:db8::1]:8443');
  assert.equal(parsed.tail, '');
  assert.equal(parsed.label, '');
});

test('parseVlessUri rejects input it cannot rewrite', () => {
  assert.equal(parseVlessUri('vmess://abc').code, 'ERR_NOT_VLESS');
  assert.equal(parseVlessUri('vless://h.example:443').code, 'ERR_NO_USER_ID');
  assert.equal(parseVlessUri('vless://id@h.example?type=xhttp').code, 'ERR_BAD_ADDRESS');
});

test('buildVlessUri with tls inserts TLS params right after encryption, without alpn the link lacked', () => {
  const uri = buildVlessUri(parseVlessUri(SAMPLE), { tls: true });
  assert.equal(uri, 'vless://2898f95d-52cb-43de-8603-d72b9c01bc88@vpnus.puton.top:8444'
    + '?encryption=none&security=tls&sni=vpnus.puton.top'
    + '&extra=%7B%22mode%22%3A%22auto%22%7D&host=vpnus.puton.top&mode=auto'
    + '&path=%2Fwarp&type=xhttp#VLESS-XHTTP-WARP-8444-TestWARP');
  assert.ok(!/[?&]alpn=/i.test(uri));
});

test('buildVlessUri with tls keeps the original host as SNI after a swap', () => {
  const uri = buildVlessUri(parseVlessUri(SAMPLE), { authority: TARGETS.vina0d.authority, tls: true });
  assert.ok(uri.includes('@vina.puton.top:443?encryption=none&security=tls&sni=vpnus.puton.top&'));
  assert.ok(uri.includes('&host=vpnus.puton.top&'));
  assert.equal(uri.match(/[?&]security=/g).length, 1);
});

test('buildVlessUri with tls replaces an existing alpn with h2,http/1.1 and handles a missing query', () => {
  const withOld = parseVlessUri('vless://id@a.example:443?type=ws&SNI=old&ALPN=h3%2Ch2&encryption=none#x');
  const uri = buildVlessUri(withOld, { tls: true });
  assert.equal(uri,
    'vless://id@a.example:443?type=ws&encryption=none&security=tls&alpn=h2%2Chttp%2F1.1&sni=a.example#x');
  assert.equal(new URL(uri).searchParams.get('alpn'), 'h2,http/1.1');
  assert.equal(buildVlessUri(parseVlessUri('vless://id@[2001:db8::1]:443'), { tls: true }),
    'vless://id@[2001:db8::1]:443?security=tls&sni=2001%3Adb8%3A%3A1');
});

test('buildVlessUri never emits a parameter twice, keeping the first value', () => {
  const dup = parseVlessUri('vless://id@a.example:443?type=xhttp&Path=%2Fa&encryption=none&path=%2Fb'
    + '&type=ws&security=none&SECURITY=reality&sni=x&sni=y&host=h#lbl');
  assert.equal(buildVlessUri(dup),
    'vless://id@a.example:443?type=xhttp&Path=%2Fa&encryption=none&security=none&sni=x&host=h#lbl');
  assert.equal(buildVlessUri(dup, { tls: true }),
    'vless://id@a.example:443?type=xhttp&Path=%2Fa&encryption=none&security=tls'
    + '&sni=h&host=h#lbl');
  for (const uri of [buildVlessUri(dup), buildVlessUri(dup, { tls: true })]) {
    const keys = uri.split('#')[0].split('?')[1].split('&').map((p) => p.split('=')[0].toLowerCase());
    assert.equal(new Set(keys).size, keys.length, uri);
  }
});

test('buildVlessUri with tls derives sni from host parameter', () => {
  const sampleWithCustomHost = parseVlessUri('vless://uuid@server.com:8444?type=xhttp&encryption=none&host=warpvpn.puton.top#Test');
  const uri = buildVlessUri(sampleWithCustomHost, { authority: 'vina.puton.top:443', tls: true });
  assert.ok(uri.includes('sni=warpvpn.puton.top'));
  assert.ok(uri.includes('host=warpvpn.puton.top'));
  assert.ok(uri.startsWith('vless://uuid@vina.puton.top:443?'));
});

test('normalizeAuthority reduces hosts and URLs to host:port', () => {
  const cases = [
    ['example.com:8443', 'example.com:8443'],
    ['  Example.COM  ', 'example.com:443'],
    ['https://cdn.example.com/some/path?x=1#y', 'cdn.example.com:443'],
    ['http://cdn.example.com', 'cdn.example.com:80'],
    ['ws://cdn.example.com:2052/ws', 'cdn.example.com:2052'],
    ['user@1.2.3.4:2083', '1.2.3.4:2083'],
    ['[2001:db8::1]', '[2001:db8::1]:443'],
    ['https://[2001:db8::1]:8443/', '[2001:db8::1]:8443'],
  ];
  for (const [input, expected] of cases) {
    assert.deepEqual(normalizeAuthority(input), { ok: true, authority: expected }, input);
  }
});

test('normalizeAuthority rejects empty and malformed addresses', () => {
  assert.equal(normalizeAuthority('   ').code, 'ERR_ADDRESS_EMPTY');
  assert.equal(normalizeAuthority('example.com:99999').code, 'ERR_BAD_ADDRESS');
  assert.equal(normalizeAuthority('example.com:0').code, 'ERR_BAD_ADDRESS');
  assert.equal(normalizeAuthority('2001:db8::1').code, 'ERR_BAD_ADDRESS');
  assert.equal(normalizeAuthority('https://').code, 'ERR_BAD_ADDRESS');
  assert.equal(normalizeAuthority('bad host:443').code, 'ERR_BAD_ADDRESS');
});

test('toFileName keeps letters and digits and falls back to vless.png', () => {
  assert.equal(toFileName('VLESS WARP / Nhà 1'), 'VLESS_WARP_Nhà_1.png');
  assert.equal(toFileName('  '), 'vless.png');
});
