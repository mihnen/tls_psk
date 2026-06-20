import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:tls_psk/tls_psk.dart';

void main() => runApp(const TlsPskExampleApp());

class TlsPskExampleApp extends StatefulWidget {
  const TlsPskExampleApp({super.key});

  @override
  State<TlsPskExampleApp> createState() => _TlsPskExampleAppState();
}

class _TlsPskExampleAppState extends State<TlsPskExampleApp> {
  final _host = TextEditingController(text: '127.0.0.1');
  final _port = TextEditingController(text: '11999');
  final _pskHex = TextEditingController(text: '0123456789abcdef0123456789abcdef');
  final _identity = TextEditingController(text: 'Client_identity');
  String _status = '';
  bool _busy = false;

  Uint8List _hex(String s) => Uint8List.fromList([
        for (var i = 0; i + 1 < s.length; i += 2) int.parse(s.substring(i, i + 2), radix: 16),
      ]);

  Future<void> _connect() async {
    setState(() {
      _busy = true;
      _status = 'connecting…';
    });
    try {
      final sock = await TlsPskSocket.connect(
        _host.text,
        int.parse(_port.text),
        psk: _hex(_pskHex.text),
        identity: utf8.encode(_identity.text),
      );
      final reply = StringBuffer();
      sock.stream.listen((d) => setState(() => _status = 'echo: ${reply..write(utf8.decode(d))}'));
      sock.add(utf8.encode('hello over tls-psk\n'));
      setState(() => _status = 'handshake OK (${TlsPskSocket.version})');
    } catch (e) {
      setState(() => _status = '$e');
    } finally {
      setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('tls_psk example')),
        body: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              TextField(controller: _host, decoration: const InputDecoration(labelText: 'Host')),
              TextField(controller: _port, decoration: const InputDecoration(labelText: 'Port')),
              TextField(controller: _pskHex, decoration: const InputDecoration(labelText: 'PSK (hex)')),
              TextField(controller: _identity, decoration: const InputDecoration(labelText: 'Identity')),
              const SizedBox(height: 16),
              FilledButton(
                onPressed: _busy ? null : _connect,
                child: const Text('Connect'),
              ),
              const SizedBox(height: 16),
              Text(_status),
            ],
          ),
        ),
      ),
    );
  }
}
